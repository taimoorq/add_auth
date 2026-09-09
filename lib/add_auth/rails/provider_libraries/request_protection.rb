# frozen_string_literal: true

module AddAuth
  module Rails
    module ProviderLibraries
      # Mint the form token with the actual maintained OmniAuth validator. A
      # Rails adopter may already configure its session key; using a separate
      # default Rack validator would generate a token that cannot be accepted.
      module RequestProtection
        module_function

        def validator
          return unless defined?(::OmniAuth::AuthenticityTokenProtection)
          require "rack/protection"
          phase = ::OmniAuth.config.request_validation_phase
          candidate = (phase.is_a?(Class) && phase <= ::Rack::Protection::AuthenticityToken) ? phase.new : phase
          candidate if candidate.is_a?(::Rack::Protection::AuthenticityToken) || rails_validator?(candidate)
        end

        def token(session:, rails_token: nil)
          configured = validator
          raise AddAuth::Error, "configure a supported OmniAuth request validator" unless configured
          if rails_validator?(configured)
            raise AddAuth::Error, "Rails request token is unavailable" unless rails_token.respond_to?(:call)
            return rails_token.call
          end
          configured.mask_authenticity_token(session)
        end

        def parameter
          configured = validator
          raise AddAuth::Error, "configure a supported OmniAuth request validator" unless configured
          rails_validator?(configured) ? ::ActionController::Base.request_forgery_protection_token : configured.options.fetch(:authenticity_param)
        end

        def rails_validator?(candidate)
          defined?(::OmniAuth::RailsCsrfProtection::TokenVerifier) && candidate.is_a?(::OmniAuth::RailsCsrfProtection::TokenVerifier)
        end
        private_class_method :rails_validator?
      end
    end
  end
end
