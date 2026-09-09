# frozen_string_literal: true

# Optional bridge for a host that uses openid_connect directly rather than
# OmniAuth. It deliberately accepts an OpenIDConnect::AccessToken obtained by
# the server-side authorization-code exchange, never `params[:id_token]`.
module AddAuth
  module Rails
    module ProviderLibraries
      module OpenIdConnect
        class CallbackResult
          attr_reader :issuer, :audience, :subject, :authenticated_at, :provenance

          def self.capture(access_token:, verification_key:, issuer:, audience:, nonce:, provenance:)
            return unless defined?(::OpenIDConnect::AccessToken) && access_token.is_a?(::OpenIDConnect::AccessToken)
            return unless access_token.id_token.is_a?(String) && !access_token.id_token.empty?

            # `decode` performs JWS verification using the discovery/JWKS key
            # (or an equivalent pinned verification key); `verify!` performs
            # the OIDC issuer, audience, expiration and nonce checks. AddAuth
            # deliberately delegates both operations to openid_connect.
            token = ::OpenIDConnect::ResponseObject::IdToken.decode(access_token.id_token, verification_key)
            token.verify!(issuer: issuer, audience: audience, nonce: nonce)
            new(issuer: token.iss, audience: audience_for(token.aud, audience), subject: token.sub,
              authenticated_at: token.auth_time && Time.at(token.auth_time).utc, provenance: provenance)
          rescue
            nil
          end

          def initialize(issuer:, audience:, subject:, authenticated_at:, provenance:)
            @issuer = text(issuer)
            @audience = text(audience)
            @subject = text(subject)
            @authenticated_at = authenticated_at&.dup&.freeze
            @provenance = text(provenance)
            freeze
          end
          private_class_method :new

          def to_verified_claims(transaction:)
            return unless transaction.respond_to?(:id)

            {issuer: issuer, audience: audience, subject: subject, authenticated_at: authenticated_at, provenance: provenance}
          end

          def inspect = "#<AddAuth::Rails::ProviderLibraries::OpenIdConnect::CallbackResult [FILTERED]>"

          def self.audience_for(value, expected)
            Array(value).find { |candidate| candidate == expected }
          end
          private_class_method :audience_for

          def text(value)
            raise ArgumentError, "invalid verified OIDC claim" unless value.is_a?(String) && value.valid_encoding? &&
              value.bytesize.between?(1, 2048) && !value.match?(/[\x00-\x1f\x7f]/)

            value.dup.freeze
          end
        end
      end
    end
  end
end
