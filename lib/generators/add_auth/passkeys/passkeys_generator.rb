# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class PasskeysGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies
        invoke "add_auth:step_up"
        invoke "add_auth:notifications"
      end

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_passkeys.rb")].any?
          migration_template "add_add_auth_passkeys.rb.tt", "db/migrate/add_add_auth_passkeys.rb"
        end
        %w[credential ceremony].each { |name| copy_file "add_auth_#{name}.rb", "app/models/add_auth_#{name}.rb", skip: true }
      end

      def wiring
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("# AddAuth passkeys")
          route <<~ROUTES
            # AddAuth passkeys
            get "add_auth/passkey.js", to: "add_auth/assets#passkey"
            get "add_auth/codec.js", to: "add_auth/assets#codec"
            get "passkeys", to: "add_auth/passkeys#index"
            post "passkeys/options", to: "add_auth/passkeys#registration_options"
            post "passkeys", to: "add_auth/passkeys#register"
            post "passkeys/sign-in/options", to: "add_auth/passkeys#authentication_options"
            post "passkeys/sign-in", to: "add_auth/passkeys#authenticate"
            post "passkeys/cancel", to: "add_auth/passkeys#cancel"
            post "passkeys/policy", to: "add_auth/passkeys#change_policy"
            patch "passkeys/:id", to: "add_auth/passkeys#rename"
            delete "passkeys/:id", to: "add_auth/passkeys#remove"
            post "reauthenticate/passkey/options", to: "add_auth/passkeys#reauthentication_options"
            post "reauthenticate/passkey", to: "add_auth/passkeys#reauthenticate"
            get "recover", to: "add_auth/recoveries#new"
            post "recover/email", to: "add_auth/recoveries#request_link"
            get "recover/check-email", to: "add_auth/recoveries#check_email"
            get "recover/link", to: "add_auth/recoveries#link"
            post "recover/link", to: "add_auth/recoveries#confirm"
          ROUTES
        end
        path = "config/initializers/add_auth.rb"
        unless File.read(File.join(destination_root, path)).include?("config.passkeys.enabled = true")
          append_to_file path, <<~CONFIG

            AddAuth.configure do |config|
              config.passkeys.enabled = true
              # REQUIRED: stable RP ID and exact deployment origins, never request Host.
              # config.passkeys.rp_id = "example.com"
              # config.passkeys.origins = ["https://app.example.com"]
              # config.passkeys.name = "Your app"
              # Shared anonymous ceremony budget per five minutes; positive integer.
              # config.passkeys.anonymous_limit = 1000
              # Schedule add_auth:deliver_pending every minute. Production doctor
              # requires a completed cleanup within the last two minutes.
              # REQUIRED for email replacement: a host-verified recovery address.
              # config.trusted_recovery_address = ->(user) { user.email_address if user.confirmed? }
              # REQUIRED before strict activation: your documented support route.
              # config.support_url = "/support"
            end
          CONFIG
        end
        say "Review and migrate before enabling traffic. Configure RP/origins, trusted recovery and notifications; run add_auth:doctor."
      end
    end
  end
end
