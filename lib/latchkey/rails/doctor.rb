# frozen_string_literal: true

require "latchkey/rails/ejection"

module Latchkey
  module Rails
    class Doctor
      attr_reader :ejections

      SESSION_COLUMNS = %w[user_id token_digest authenticated_with authenticated_at expires_at last_seen_at revoked_at
        elevated_at elevated_with elevation_purpose elevation_credential_id elevation_uv].freeze
      TOKEN_COLUMNS = %w[user_id digest identifier_digest purpose expires_at consumed_at revoked_at delivery_payload
        request_id delivery_lease_key delivery_lease_until delivered_at].freeze

      def call
        @problems = []
        config = Latchkey.configuration
        if config.session.enabled
          columns(::Session, SESSION_COLUMNS, "session")
          unique_index(::Session, "token_digest")
          unique_index(::User, "email_address")
          check("Include Latchkey authentication after the host Authentication concern") do
            ::ApplicationController.instance_method(:find_session_by_cookie).owner == Authentication
          end
          %i[latchkey_write_cookie latchkey_accept latchkey_replacement_session terminate_session].each do |hook|
            check("Restore the hardened cookie/session hook #{hook}") do
              ::ApplicationController.instance_method(hook).owner == Authentication
            end
          end
          check("Include Latchkey::Rails::UserLifecycle in User") { ::User < UserLifecycle }
          check("Install the shared password entry in SessionsController") { ::SessionsController < PasswordEntry }
          %w[/sign-in /latchkey.css /latchkey/boot.js /latchkey/turbo.js /latchkey/stimulus.js /latchkey/challenge.js /sessions].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
          check("Configure valid session timeouts and digest adapters") { Runtime.sessions }
          cache = config.rate_limit_store || ::Rails.cache
          check("Configure an atomic rate-limit cache") do
            key = "latchkey:doctor:#{SecureRandom.hex(16)}"
            begin
              cache.increment(key, 1, expires_in: 30, initial: 0) == 1 && cache.increment(key, 1, expires_in: 30, initial: 0) == 2
            ensure
              cache.delete(key)
            end
          end
          if ::Rails.env.production?
            check("Enable CSRF protection for authentication") { ::ApplicationController.allow_forgery_protection }
            check("Use a shared rate-limit cache in production") do
              !cache.is_a?(ActiveSupport::Cache::MemoryStore) && !cache.is_a?(ActiveSupport::Cache::NullStore)
            end
          end
        end
        if config.email_link.enabled
          check("Enable session_upgrade before email_link") { config.session.enabled }
          check("Configure mail_from") { config.mail_from.is_a?(String) && !config.mail_from.strip.empty? }
          check("Configure base_url as a fixed HTTPS origin (HTTP only outside production)") { Runtime.sign_in_url("validation") }
          columns(defined?(::LatchkeySignInToken) && ::LatchkeySignInToken, TOKEN_COLUMNS, "email delivery")
          if defined?(::LatchkeySignInToken)
            unique_index(::LatchkeySignInToken, "digest")
            unique_index(::LatchkeySignInToken, "request_id")
          end
          if config.email_link.same_browser
            columns(defined?(::LatchkeySignInToken) && ::LatchkeySignInToken, ["browser_digest"], "email browser binding")
          end
          check("Enable Action Mailer delivery") { ActionMailer::Base.perform_deliveries && ActionMailer::Base.raise_delivery_errors }
          if ::Rails.env.production?
            check("Use a durable job adapter in production") { !ActiveJob::Base.queue_adapter.class.name.match?(/Async|Inline|Test/) }
            check("Configure production mail delivery") { !%i[test file].include?(ActionMailer::Base.delivery_method) }
          end
        end
        if config.passkeys.enabled
          check("Configure passkey prerequisites, RP ID, exact origins, anonymous_limit and a safe support path") { Runtime.passkeys }
          if ::Rails.env.production?
            check("Schedule latchkey:deliver_pending every minute; no successful cleanup in the last two minutes") { Runtime.maintenance_current? }
          end
          columns(::User, %w[webauthn_id latchkey_strict latchkey_policy_version], "passkeys")
          columns(::Session, %w[authentication_policy_version authentication_credential_id authentication_uv], "passkeys")
          columns(defined?(::LatchkeyCredential) && ::LatchkeyCredential,
            %w[user_id external_id public_key sign_count revoked_at backup_eligible backup_state], "passkeys")
          columns(defined?(::LatchkeyCeremony) && ::LatchkeyCeremony,
            %w[digest challenge kind browser_digest configuration_digest session_id session_digest expires_at consumed_at], "passkeys")
          unique_index(::User, "webauthn_id")
          unique_index(::LatchkeyCredential, "external_id") if defined?(::LatchkeyCredential)
          unique_index(::LatchkeyCeremony, "digest") if defined?(::LatchkeyCeremony)
          check("Supply a trusted recovery address callback") { config.trusted_recovery_address.respond_to?(:call) }
          %w[/passkeys /recover /latchkey/passkey.js /latchkey/codec.js].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
          check("Keep a support route for strict accounts") do
            !::User.exists?(latchkey_strict: true) || Core::Sessions.safe_return(config.support_url)
          end
        end
        if config.notifications.enabled
          columns(defined?(::LatchkeySecurityEvent) && ::LatchkeySecurityEvent,
            %w[kind digest delivery_payload delivery_lease_key delivery_lease_until delivered_at revoked_at expires_at], "security notifications")
          check("Configure mail_from for security notifications") { config.mail_from.is_a?(String) && !config.mail_from.empty? }
          check("Enable security notification delivery errors") { ::Latchkey::SecurityMailer.raise_delivery_errors }
        end
        if config.step_up.enabled
          check("Enable session and email prerequisites for step_up") { config.session.enabled && config.email_link.enabled }
          columns(::Session, %w[elevation_version elevation_expires_at], "reauthentication")
          columns(defined?(::LatchkeySignInToken) && ::LatchkeySignInToken,
            %w[browser_digest session_id session_digest authentication_purpose], "reauthentication")
          check("Declare valid step-up purposes and safe return destinations") { Runtime.step_up_purposes.any? && Runtime.step_up_policy }
          %w[/reauthenticate /reauthenticate/link].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
        end
        if config.challenge_on.any?
          check("Unknown challenge actions") { (config.challenge_on - %i[sign_in email_link reauthenticate passkey_enrollment]).empty? }
          check("Configure a challenge provider before setting challenge_on") { !config.challenge.is_a?(Core::Challenge::Null) }
          if ::Rails.env.production?
            check("Configure challenge hostname restrictions") { config.challenge.allowed_hostnames&.any? }
          end
        end
        check("Review the ejection manifest and changed upstream files") do
          @ejections = Ejection.new(host_root: ::Rails.root).report
          @ejections.none? { |entry| entry[:missing] || entry[:upstream_changed] }
        end
        @problems
      end

      private

      def columns(model, required, feature)
        check("Run pending #{feature} migrations (required: #{required.join(", ")})") { model && (required - model.column_names).empty? }
      end

      def unique_index(model, column)
        check("Add a unique #{model.name}.#{column} index") do
          model.connection.indexes(model.table_name).any? { |index| index.unique && index.columns == [column] && !index.where }
        end
      end

      def check(message)
        @problems << message unless yield
      rescue
        @problems << message
      end
    end
  end
end
