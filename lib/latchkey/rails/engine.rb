# frozen_string_literal: true

require "turbo-rails"
require "latchkey/rails/authentication_pages"

module Latchkey
  module Rails
    # Non-isolated: host controllers/views remain in the host namespace.
    class Engine < ::Rails::Engine
      engine_name "latchkey"

      initializer "latchkey.filter_parameters" do |app|
        app.config.filter_parameters += [:token, :password, :delivery_payload, :token_digest, :encrypted_identifier, :browser_digest, :session_digest, :elevation_version, :latchkey_browser, :credential, :transaction, :challenge, :external_id, :public_key, :"cf-turnstile-response", :"g-recaptcha-response"]
      end

      config.to_prepare do
        if Latchkey.configuration.session.enabled
          require "latchkey/rails/password_entry"
          require "latchkey/rails/elevation"
          ::ApplicationController.include Latchkey::Rails::Elevation
          ::SessionsController.include Latchkey::Rails::PasswordEntry
        end
      end

      initializer "latchkey.configuration", before: :load_config_initializers do |app|
        Latchkey.configuration.digest_secret ||= -> {
          app.key_generator.generate_key("latchkey.digest-base-secret.v1", 32)
        }
      end
    end
  end
end
