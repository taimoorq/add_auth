# frozen_string_literal: true

require "turbo-rails"
require "add_auth/rails/authentication_pages"
require "add_auth/rails/provider_libraries/callback_route"

module AddAuth
  module Rails
    # Non-isolated: host controllers/views remain in the host namespace.
    class Engine < ::Rails::Engine
      engine_name "add_auth"

      initializer "add_auth.filter_parameters" do |app|
        app.config.filter_parameters += [:token, :password, :enrollment_payload, :code, :state, :nonce, :id_token, :access_token, :refresh_token, :client_secret, :authorization_code, :raw_info, :id_info, :delivery_payload, :token_digest, :encrypted_identifier, :browser_digest, :session_digest, :elevation_version, :add_auth_browser, :credential, :transaction, :challenge, :external_id, :public_key, :"cf-turnstile-response", :"g-recaptcha-response"]
      end

      config.to_prepare do
        if AddAuth.configuration.session.enabled
          require "add_auth/rails/password_entry"
          require "add_auth/rails/elevation"
          ::ApplicationController.include AddAuth::Rails::Elevation
          if AddAuth.configuration.passwords_enabled || defined?(::SessionsController)
            ::SessionsController.include AddAuth::Rails::PasswordEntry
          end
          if defined?(::PasswordsController)
            require "add_auth/rails/account_password_entry"
            ::PasswordsController.include AddAuth::Rails::AccountPasswordEntry
          end
        end
      end

      initializer "add_auth.configuration", before: :load_config_initializers do |app|
        AddAuth.configuration.digest_secret ||= -> {
          app.key_generator.generate_key("add_auth.digest-base-secret.v1", 32)
        }
      end
    end
  end
end
