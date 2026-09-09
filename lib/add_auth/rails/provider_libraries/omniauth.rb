# frozen_string_literal: true

# This adapter deliberately has no `require "omniauth"`: provider gems remain
# host-selected optional dependencies. It accepts only the in-process Rack
# callback product that OmniAuth installs after a strategy completes. It never
# accepts HTTP parameters or an auth hash supplied by a controller.
module AddAuth
  module Rails
    module ProviderLibraries
      module OmniAuth
        # An immutable, allowlisted projection of an OmniAuth callback. The raw
        # auth hash can include OAuth credentials and profile data, so this
        # object intentionally exposes neither. A configured Verifier maps only
        # the identity claims it needs into Core's trusted verifier contract.
        class CallbackResult
          attr_reader :provider, :strategy_class

          def self.capture(env:, provider:)
            return unless env.respond_to?(:[])

            strategy = env["omniauth.strategy"]
            auth = env["omniauth.auth"]
            return unless defined?(::OmniAuth::Strategy) && strategy.is_a?(::OmniAuth::Strategy)
            return unless defined?(::OmniAuth::AuthHash) && auth.is_a?(::OmniAuth::AuthHash)
            return unless strategy.name.to_s == provider.to_s && auth.provider.to_s == provider.to_s

            new(provider: provider.to_s, strategy_class: strategy.class.name, auth: auth)
          end

          def initialize(provider:, strategy_class:, auth:)
            @provider = provider.dup.freeze
            @strategy_class = strategy_class.dup.freeze
            @auth = auth
            freeze
          end
          private_class_method :new

          # A mapping is declared in trusted server configuration, rather than
          # selected by a request. Its paths are evaluated against the Rack
          # result before this object crosses into Core.
          def values(mapping)
            mapping.transform_values { |path| read(path) }
          end

          def inspect = "#<AddAuth::Rails::ProviderLibraries::OmniAuth::CallbackResult [FILTERED]>"

          private

          def read(path)
            Array(path).reduce(@auth) do |value, key|
              if value.respond_to?(:[])
                value[key] || value[key.to_s] || value[key.to_sym]
              end
            end
          rescue NoMethodError
            nil
          end
        end

        # Builds the callable supplied to
        # Core::ExternalIdentities::Configuration#verifier. It binds that
        # configuration to one OmniAuth strategy and one static claim map. The
        # provider strategy remains responsible for authorization-code exchange,
        # JWKS/signature validation, state and nonce verification; this adapter
        # only prevents an HTTP parameter/raw profile from impersonating that
        # completed strategy result.
        class Verifier
          DEFAULT_MAPPING = {
            issuer: %i[extra id_info iss],
            audience: %i[extra id_info aud],
            subject: %i[extra id_info sub],
            authenticated_at: %i[extra id_info auth_time]
          }.freeze

          def initialize(provider:, provenance:, mapping: DEFAULT_MAPPING)
            @provider = text(provider.to_s)
            @provenance = text(provenance)
            @mapping = normalize_mapping(mapping)
            freeze
          end

          def call(server_result:, transaction:)
            return unless server_result.is_a?(CallbackResult) && server_result.provider == @provider
            return unless transaction.respond_to?(:id)

            claims = server_result.values(@mapping)
            issuer, audience, subject = claims.values_at(:issuer, :audience, :subject)
            return unless [issuer, audience, subject].all? { |value| valid_text?(value) }
            return unless subject == server_result.values(subject: :uid).fetch(:subject)

            authenticated_at = time(claims[:authenticated_at])
            return if claims[:authenticated_at] && !authenticated_at

            {issuer: issuer, audience: audience, subject: subject, provenance: @provenance,
             authenticated_at: authenticated_at}
          end

          private

          def normalize_mapping(mapping)
            required = %i[issuer audience subject]
            raise ArgumentError, "provider claim mapping must contain issuer, audience and subject" unless mapping.is_a?(Hash) &&
              (required - mapping.keys.map(&:to_sym)).empty?

            mapping.to_h.transform_keys(&:to_sym).transform_values do |path|
              parts = Array(path)
              raise ArgumentError, "provider claim paths must be nonempty" if parts.empty? || parts.any? { |part| !part.is_a?(String) && !part.is_a?(Symbol) }

              parts.map(&:to_sym).freeze
            end.freeze
          end

          def text(value)
            raise ArgumentError, "invalid provider verifier value" unless valid_text?(value)

            value.dup.freeze
          end

          def valid_text?(value)
            value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, 2048) && !value.match?(/[\x00-\x1f\x7f]/)
          end

          def time(value)
            return value if value.is_a?(Time)
            return unless value.is_a?(Integer) || value.is_a?(Float)
            return if value.is_a?(Float) && !value.finite?

            Time.at(value).utc
          rescue ArgumentError, RangeError
            nil
          end
        end
      end
    end
  end
end
