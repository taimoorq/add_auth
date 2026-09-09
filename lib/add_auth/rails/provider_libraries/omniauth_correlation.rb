# frozen_string_literal: true

require "rack/request"

module AddAuth
  module Rails
    module ProviderLibraries
      # Correlates the Core one-use transaction with OmniAuth's already-CSRF-
      # protected state value. It stores only opaque Core data in the ordinary
      # application session; OAuth tokens, profile data, and claims never enter
      # this boundary. Apple form_post needs its own cookie transport because
      # its cross-site callback deliberately lacks this session.
      class OmniAuthCorrelation
        PENDING_KEY = "add_auth.provider_pending"
        CORRELATIONS_KEY = "add_auth.provider_correlations"
        ENV_KEY = "add_auth.provider_correlation"

        def self.remember!(session:, provider:, transaction:, browser_secret:, configuration_id:, purpose:, remember: false)
          payload = {"provider" => provider.to_s, "transaction" => transaction, "browser_secret" => browser_secret,
                     "configuration_id" => configuration_id, "purpose" => purpose.to_s, "remember" => remember == true}
          raise ArgumentError, "provider transaction correlation is invalid" unless valid_payload?(payload)

          session[PENDING_KEY] ||= {}
          raise ArgumentError, "provider transaction correlation is invalid" unless session[PENDING_KEY].is_a?(Hash)

          session[PENDING_KEY][payload.fetch("provider")] = payload
        end

        def self.valid_payload?(payload)
          payload.is_a?(Hash) && %w[provider transaction browser_secret configuration_id purpose].all? { |key| text?(payload[key]) } &&
            [true, false].include?(payload["remember"])
        end

        def self.text?(value)
          value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, 2048) && !value.match?(/[\x00-\x1f\x7f]/)
        end
        private_class_method :text?, :valid_payload?

        def initialize(app, providers:, lifetime: 600, clock: -> { Time.now })
          raise ArgumentError, "provider correlation lifetime is invalid" unless lifetime.is_a?(Integer) && lifetime.between?(1, 600)
          raise ArgumentError, "provider correlation providers are invalid" unless providers.is_a?(Array) && providers.all? { |name| self.class.send(:text?, name.to_s) }

          @app, @providers, @lifetime, @clock = app, providers.map(&:to_s).freeze, lifetime, clock
        end

        def call(env)
          request = Rack::Request.new(env)
          provider = provider_for(request.path_info)
          return @app.call(env) unless provider

          return request.post? ? start(env, provider) : @app.call(env) if request.path_info == "/auth/#{provider}"
          callback(env, request, provider)
        end

        private

        def provider_for(path)
          @providers.find { |provider| ["/auth/#{provider}", "/auth/#{provider}/callback"].include?(path) }
        end

        def start(env, provider)
          session = env.fetch("rack.session", {})
          pending = session.fetch(PENDING_KEY, {}).delete(provider)
          return @app.call(env) if pending.nil?
          return failure unless self.class.send(:valid_payload?, pending) && pending.fetch("provider") == provider

          status, headers, body = @app.call(env)
          state = session["omniauth.state"]
          return [status, headers, body] unless status.between?(300, 399) && self.class.send(:text?, state)

          correlations = session[CORRELATIONS_KEY] ||= {}
          return failure unless correlations.is_a?(Hash)

          purge!(correlations)
          correlations[state] = pending.merge("expires_at" => (@clock.call + @lifetime).to_i)
          [status, headers, body]
        end

        def callback(env, request, provider)
          state = request.params["state"]
          session = env.fetch("rack.session", {})
          correlations = session.fetch(CORRELATIONS_KEY, {})
          payload = correlations.delete(state) if self.class.send(:text?, state) && correlations.is_a?(Hash)
          # A shared OmniAuth stack may serve other host-owned OAuth journeys.
          # Only attach authority correlation for a transaction we started. The
          # AddAuth callback controller independently rejects missing correlation.
          return @app.call(env) if payload.nil?
          return failure unless self.class.send(:valid_payload?, payload) && payload.fetch("provider") == provider &&
            payload.fetch("expires_at", 0).is_a?(Integer) && payload.fetch("expires_at") > @clock.call.to_i

          env[ENV_KEY] = payload.slice("transaction", "browser_secret", "configuration_id", "purpose", "remember")
          @app.call(env)
        end

        def purge!(correlations)
          now = @clock.call.to_i
          correlations.delete_if { |_state, payload| !payload.is_a?(Hash) || payload["expires_at"].to_i <= now }
          correlations.shift while correlations.size >= 8
        end

        def failure
          [422, {"content-type" => "text/plain", "cache-control" => "no-store"}, ["Provider sign-in could not be verified."]]
        end
      end
    end
  end
end
