# frozen_string_literal: true

# Optional adapter: the host installs and requires ruby-jwt. No OAuth strategy,
# global library setting or provider credential storage is introduced.
module AddAuth
  module Rails
    module ProviderLibraries
      module AppleNative
        ISSUER = "https://appleid.apple.com"
        PURPOSES = [Core::ExternalIdentities::NATIVE, Core::ExternalIdentities::NATIVE_ENROLL].freeze

        class CallbackResult
          def self.capture(identity_token:, pending:, nonce:, jwks:)
            return unless defined?(::JWT) && pending.is_a?(Core::ExternalIdentities::Pending) &&
              PURPOSES.include?(pending.purpose) && pending.configuration.issuer == ISSUER &&
              identity_token.is_a?(String) && identity_token.bytesize.between?(1, 16_384) && nonce.is_a?(String)
            claims, = ::JWT.decode(identity_token, nil, true, algorithms: ["RS256"], jwks: jwks, allow_nil_kid: false,
              iss: ISSUER, verify_iss: true, aud: pending.configuration.audience, verify_aud: true, verify_iat: true,
              required_claims: %w[iss aud sub exp iat nonce])
            signed_nonce = claims["nonce"]
            return unless signed_nonce.is_a?(String) && signed_nonce.bytesize == nonce.bytesize &&
              OpenSSL.fixed_length_secure_compare(signed_nonce, nonce) && claims["iat"].is_a?(Integer) && claims["exp"].is_a?(Integer) &&
              claims["iat"] >= pending.issued_at.to_i && claims["aud"] == pending.configuration.audience
            new(pending: pending, subject: claims["sub"])
          rescue ::JWT::DecodeError, ArgumentError
            nil
          end

          def initialize(pending:, subject:)
            @transaction_id = pending.id
            @configuration = pending.configuration
            @purpose = pending.purpose
            @subject = Core::ExternalIdentities::Configuration.text(subject)
            freeze
          end
          private_class_method :new

          def verified_claims(transaction:)
            return unless transaction.is_a?(Core::ExternalIdentities::Pending) && transaction.id == @transaction_id &&
              transaction.configuration.equal?(@configuration) && transaction.purpose == @purpose
            {issuer: ISSUER, audience: @configuration.audience, subject: @subject, provenance: "ruby-jwt/apple-native-v1"}
          end

          def inspect = "#<AddAuth::Rails::ProviderLibraries::AppleNative::CallbackResult [FILTERED]>"
        end

        class Verifier
          def call(server_result:, transaction:)
            server_result.verified_claims(transaction: transaction) if server_result.is_a?(CallbackResult)
          end
        end
      end
    end
  end
end
