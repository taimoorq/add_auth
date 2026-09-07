# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Latchkey
  module Generators
    class PasskeysGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies
        invoke "latchkey:step_up"
        invoke "latchkey:notifications"
      end

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_add_latchkey_passkeys.rb")].any?
          migration_template "add_latchkey_passkeys.rb.tt", "db/migrate/add_latchkey_passkeys.rb"
        end
        %w[credential ceremony].each { |name| copy_file "latchkey_#{name}.rb", "app/models/latchkey_#{name}.rb", skip: true }
      end

      def wiring
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("# Latchkey passkeys")
          route <<~ROUTES
            # Latchkey passkeys
            get "latchkey/passkey.js", to: "latchkey/assets#passkey"
            get "latchkey/codec.js", to: "latchkey/assets#codec"
            get "passkeys", to: "latchkey/passkeys#index"
            post "passkeys/options", to: "latchkey/passkeys#registration_options"
            post "passkeys", to: "latchkey/passkeys#register"
            post "passkeys/sign-in/options", to: "latchkey/passkeys#authentication_options"
            post "passkeys/sign-in", to: "latchkey/passkeys#authenticate"
            post "passkeys/cancel", to: "latchkey/passkeys#cancel"
            post "passkeys/policy", to: "latchkey/passkeys#change_policy"
            patch "passkeys/:id", to: "latchkey/passkeys#rename"
            delete "passkeys/:id", to: "latchkey/passkeys#remove"
            post "reauthenticate/passkey/options", to: "latchkey/passkeys#reauthentication_options"
            post "reauthenticate/passkey", to: "latchkey/passkeys#reauthenticate"
            get "recover", to: "latchkey/recoveries#new"
            post "recover/email", to: "latchkey/recoveries#request_link"
            get "recover/check-email", to: "latchkey/recoveries#check_email"
            get "recover/link", to: "latchkey/recoveries#link"
            post "recover/link", to: "latchkey/recoveries#confirm"
          ROUTES
        end
        path = "config/initializers/latchkey.rb"
        unless File.read(File.join(destination_root, path)).include?("config.passkeys.enabled = true")
          append_to_file path, <<~CONFIG

            Latchkey.configure do |config|
              config.passkeys.enabled = true
              # REQUIRED: stable RP ID and exact deployment origins, never request Host.
              # config.passkeys.rp_id = "example.com"
              # config.passkeys.origins = ["https://app.example.com"]
              # config.passkeys.name = "Your app"
              # Shared anonymous ceremony budget per five minutes; positive integer.
              # config.passkeys.anonymous_limit = 1000
              # Schedule latchkey:deliver_pending every minute. Production doctor
              # requires a completed cleanup within the last two minutes.
              # REQUIRED for email replacement: a host-verified recovery address.
              # config.trusted_recovery_address = ->(user) { user.email_address if user.confirmed? }
              # REQUIRED before strict activation: your documented support route.
              # config.support_url = "/support"
            end
          CONFIG
        end
        say "Review and migrate before enabling traffic. Configure RP/origins, trusted recovery and notifications; run latchkey:doctor."
      end
    end
  end
end
