# frozen_string_literal: true

require "add_auth/rails/ejection"
require "add_auth/rails/rate_limit_cache"

module AddAuth
  module Rails
    class Doctor
      attr_reader :ejections

      SESSION_COLUMNS = %w[user_id token_digest authenticated_with authenticated_at expires_at last_seen_at revoked_at
        elevated_at elevated_with elevation_purpose elevation_credential_id elevation_uv].freeze
      TOKEN_COLUMNS = %w[user_id digest identifier_digest purpose expires_at consumed_at revoked_at delivery_payload
        request_id delivery_lease_key delivery_lease_until delivered_at].freeze

      def call
        @problems = []
        config = AddAuth.configuration
        check("Configure valid maintenance batch size and retention durations") do
          Core::Maintenance.new(stores: {}, options: config.maintenance, enqueue: ->(*) {})
        end
        if config.session.enabled
          columns(::Session, SESSION_COLUMNS, "session")
          unique_index(::Session, "token_digest")
          unique_index(::User, "email_address")
          check("Include AddAuth authentication after the host Authentication concern") do
            ::ApplicationController.instance_method(:find_session_by_cookie).owner == Authentication
          end
          %i[add_auth_write_cookie add_auth_accept add_auth_replacement_session terminate_session require_add_auth_authentication].each do |hook|
            check("Restore the hardened cookie/session hook #{hook}") do
              ::ApplicationController.instance_method(hook).owner == Authentication
            end
          end
          check("Include AddAuth::Rails::UserLifecycle in User") { ::User < UserLifecycle }
          check("Set passwords_enabled to true or false") { [true, false].include?(config.passwords_enabled) }
          check("Set turbo_enabled to true or false") { [true, false].include?(config.turbo_enabled) }
          if config.passwords_enabled || defined?(::SessionsController)
            check("Install the shared password entry in SessionsController") { ::SessionsController < PasswordEntry }
          end
          if config.passwords_enabled
            check("Keep Rails password authentication on User when passwords are enabled") do
              ::User.column_names.include?("password_digest") && ::User.respond_to?(:authenticate_by)
            end
          end
          %w[/sign-in /add_auth.css /add_auth/boot.js /add_auth/turbo.js /add_auth/stimulus.js /add_auth/challenge.js /sessions].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
          check("Configure valid session timeouts and digest adapters") { Runtime.sessions }
          cache = config.rate_limit_store || ::Rails.cache
          check(RateLimitCache::INCOMPATIBLE) { RateLimitCache.validate!(cache) }
          check("Configure an atomic rate-limit cache") do
            RateLimitCache.validate!(cache)
            key = "add_auth:doctor:#{SecureRandom.hex(16)}"
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
        if config.mobile.enabled
          columns(::Session, %w[transport client_id mobile_idle_timeout], "mobile session")
          check("Configure explicit bounded mobile timeouts and registered client identifiers") { Runtime.mobile_profile }
          check("Install mobile session routes") { ::Rails.application.routes.recognize_path("/mobile/session", method: :post) }
          check("Configure mobile callbacks and Apple providers as explicit maps") do
            config.mobile.callbacks.is_a?(Hash) && config.mobile.apple_providers.is_a?(Hash)
          end
          if config.mobile.callbacks.is_a?(Hash) && config.mobile.callbacks.any?
            check("Enable reviewed provider integration before mobile handoffs") { config.external_identities.enabled }
            columns(defined?(::AddAuthMobileHandoff) && ::AddAuthMobileHandoff,
              %w[user_id external_digest digest client_id callback state challenge_digest credential_id credential_version policy_version authenticated_at issued_at expires_at consumed_at], "mobile handoff")
            unique_index(::AddAuthMobileHandoff, "digest") if defined?(::AddAuthMobileHandoff)
            unique_index(::AddAuthMobileHandoff, "external_digest") if defined?(::AddAuthMobileHandoff)
            check("Use one database pool for mobile handoffs, accounts and sessions") { Runtime.mobile_handoffs }
          end
          if config.mobile.apple_providers.is_a?(Hash) && config.mobile.apple_providers.any?
            check("Configure the optional native Apple library and exact client mapping") { Runtime.native_apple }
          end
        end
        if config.email_link.enabled
          check("Enable session_upgrade before email_link") { config.session.enabled }
          check("Configure base_url as a fixed HTTPS origin (HTTP only outside production)") { Runtime.sign_in_url("validation") }
          columns(defined?(::AddAuthSignInToken) && ::AddAuthSignInToken, TOKEN_COLUMNS, "email delivery")
          if defined?(::AddAuthSignInToken)
            unique_index(::AddAuthSignInToken, "digest")
            unique_index(::AddAuthSignInToken, "request_id")
          end
          if config.email_link.same_browser
            columns(defined?(::AddAuthSignInToken) && ::AddAuthSignInToken, ["browser_digest"], "email browser binding")
          end
        end
        if config.external_identities.enabled
          check("Enable session and step-up prerequisites for provider sign-in") { config.session.enabled && config.step_up.enabled }
          check("Declare current password verifier support metadata") { config.current_password_support.respond_to?(:available?) }
          if config.external_identities.providers.any?
            require "add_auth/rails/provider_libraries/request_protection"
            check("Configure a supported OmniAuth request validator") { !!ProviderLibraries::RequestProtection.validator }
          end
          check("Register at least one reviewed provider profile") { config.external_identities.configurations.any? }
          columns(defined?(::AddAuthExternalIdentity) && ::AddAuthExternalIdentity,
            %w[user_id namespace provider_id issuer audience subject provenance credential_version linked_at revoked_at invalidated_at], "external identity")
          columns(defined?(::AddAuthExternalTransaction) && ::AddAuthExternalTransaction,
            %w[digest browser_digest provider_id issuer audience purpose user_id session_id session_digest policy_version issued_at expires_at consumed_at enrollment_payload], "external transaction")
          columns(::Session, %w[authentication_external_id authentication_external_version], "external session evidence")
          unique_index(::AddAuthExternalIdentity, "namespace") if defined?(::AddAuthExternalIdentity)
          unique_index(::AddAuthExternalTransaction, "digest") if defined?(::AddAuthExternalTransaction)
          check("Use one database pool for provider, account and session persistence") { Runtime.external_identities }
          config.external_identities.providers.each do |provider|
            check("Install the configured provider callback and preparation routes") do
              ::Rails.application.routes.recognize_path("/sign-in/providers/#{provider.middleware_name}", method: :post) &&
                ::Rails.application.routes.recognize_path("/auth/#{provider.middleware_name}/callback", method: provider.apple_form_post? ? :post : :get)
            end
          end
          check("Install provider account management routes") { ::Rails.application.routes.recognize_path("/account/external-identities", method: :get) }
        end
        if config.lifecycle.enabled
          if defined?(::PasswordsController)
            check("Retire stock password reset entry points through the shared account flow") { ::PasswordsController < AccountPasswordEntry }
          end
          columns(::Session, %w[remembered idle_timeout], "remembered browser sessions")
          check("Enable session, step-up and notification prerequisites for account lifecycle") { config.session.enabled && config.step_up.enabled && config.notifications.enabled }
          columns(::User, %w[confirmed_at unconfirmed_email locked_at failed_attempts disabled_at deleted_at add_auth_manual_lock add_auth_locked_until add_auth_authority], "account lifecycle")
          columns(defined?(::AddAuthAccountToken) && ::AddAuthAccountToken,
            (TOKEN_COLUMNS - %w[identifier_digest]) + %w[address_digest account_version], "account proofs")
          columns(defined?(::AddAuthAddressClaim) && ::AddAuthAddressClaim, %w[user_id digest state], "address claims")
          if defined?(::AddAuthAccountToken)
            unique_index(::AddAuthAccountToken, "digest")
            unique_index(::AddAuthAccountToken, "request_id")
          end
          unique_index(::AddAuthAddressClaim, "digest") if defined?(::AddAuthAddressClaim)
          check("Configure account policy, profile mapping and local transaction provisioning callbacks") do
            %i[eligible password_policy profile_attributes provision deletion_allowed delete_account].all? { |name| config.lifecycle.public_send(name).respond_to?(:call) }
          end
          check("Configure account proof delivery, lock policy and shared account storage") { Runtime.accounts && Runtime.password_lifecycle && Runtime.account_proof_url("validation", purpose: "confirm") }
          %w[/account/sign-up /account/requests/confirm /account/email /account/password].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
        end
        if config.email_link.enabled || config.notifications.enabled || config.lifecycle.enabled
          check("Configure mail_from") { config.mail_from.is_a?(String) && !config.mail_from.strip.empty? }
          check("Enable Action Mailer delivery") { ActionMailer::Base.perform_deliveries && ActionMailer::Base.raise_delivery_errors }
          if ::Rails.env.production?
            check("Use a durable job adapter in production") { !ActiveJob::Base.queue_adapter.class.name.match?(/Async|Inline|Test/) }
            check("Configure production mail delivery") { !%i[test file].include?(ActionMailer::Base.delivery_method) }
          end
        end
        maintenance_needed = config.passkeys.enabled || config.email_link.enabled || config.notifications.enabled || config.lifecycle.enabled || config.external_identities.enabled || config.mobile.enabled || config.maintenance.session_retention
        if ::Rails.env.production? && maintenance_needed
          check("Schedule add_auth:deliver_pending every minute; no successful cleanup in the last two minutes") { Runtime.maintenance_current? }
        end
        if config.passkeys.enabled
          check("Configure passkey prerequisites, RP ID, exact origins, anonymous_limit and a safe support path") { Runtime.passkeys }
          columns(::User, %w[webauthn_id add_auth_strict add_auth_policy_version], "passkeys")
          columns(::Session, %w[authentication_policy_version authentication_credential_id authentication_uv], "passkeys")
          columns(defined?(::AddAuthCredential) && ::AddAuthCredential,
            %w[user_id external_id public_key sign_count revoked_at backup_eligible backup_state], "passkeys")
          columns(defined?(::AddAuthCeremony) && ::AddAuthCeremony,
            %w[digest challenge kind browser_digest configuration_digest session_id session_digest expires_at consumed_at], "passkeys")
          unique_index(::User, "webauthn_id")
          unique_index(::AddAuthCredential, "external_id") if defined?(::AddAuthCredential)
          unique_index(::AddAuthCeremony, "digest") if defined?(::AddAuthCeremony)
          check("Supply a trusted recovery address callback") { config.trusted_recovery_address.respond_to?(:call) }
          %w[/passkeys /recover /add_auth/passkey.js /add_auth/codec.js].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
          check("Keep a support route for strict accounts") do
            !::User.exists?(add_auth_strict: true) || Core::Sessions.safe_return(config.support_url)
          end
        end
        if config.notifications.enabled
          columns(defined?(::AddAuthSecurityEvent) && ::AddAuthSecurityEvent,
            %w[kind digest delivery_payload delivery_lease_key delivery_lease_until delivered_at revoked_at expires_at], "security notifications")
          check("Enable security notification delivery errors") { ::AddAuth::SecurityMailer.raise_delivery_errors }
        end
        if config.step_up.enabled
          check("Enable session and email prerequisites for step_up") { config.session.enabled && config.email_link.enabled }
          columns(::Session, %w[elevation_version elevation_expires_at], "reauthentication")
          columns(defined?(::AddAuthSignInToken) && ::AddAuthSignInToken,
            %w[browser_digest session_id session_digest authentication_purpose], "reauthentication")
          check("Declare valid step-up purposes and safe return destinations") { Runtime.step_up_purposes.any? && Runtime.step_up_policy }
          %w[/reauthenticate /reauthenticate/link].each do |path|
            check("Install route #{path}") { ::Rails.application.routes.recognize_path(path, method: :get) }
          end
        end
        if config.challenge_on.any?
          check("Unknown challenge actions (email proof pages cannot load third-party challenges)") { (config.challenge_on - %i[sign_in email_link reauthenticate passkey_enrollment register account_request provider]).empty? }
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
