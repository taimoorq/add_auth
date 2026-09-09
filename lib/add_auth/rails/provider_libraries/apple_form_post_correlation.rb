# frozen_string_literal: true

require "active_support/message_encryptor"
require "rack/request"
require "rack/utils"

module AddAuth
  module Rails
    module ProviderLibraries
      # OmniAuth's Apple strategy binds state and nonce to rack.session. Apple
      # posts its callback cross-site, where a normal SameSite=Lax Rails session
      # is intentionally absent. This tiny Rack wrapper copies only those
      # verifier inputs and the Core browser correlation into a separately
      # encrypted, HttpOnly, Secure, SameSite=None cookie scoped to Apple's
      # callback path. It never changes the application's normal session cookie.
      class AppleFormPostCorrelation
        COOKIE = "add_auth_apple_callback"
        PENDING_KEY = "add_auth.apple_pending"
        START_PATH = "/auth/apple"
        CALLBACK_PATH = "/auth/apple/callback"
        PURPOSE = "add_auth.apple-form-post.v1"

        def self.remember!(session:, transaction:, browser_secret:, configuration_id:, purpose:, remember: false)
          raise ArgumentError, "Apple provider transaction is invalid" unless text?(transaction)
          raise ArgumentError, "Apple provider browser secret is invalid" unless text?(browser_secret)
          raise ArgumentError, "Apple provider configuration is invalid" unless text?(configuration_id)
          raise ArgumentError, "Apple provider purpose is invalid" unless text?(purpose.to_s)

          session[PENDING_KEY] = {"transaction" => transaction, "browser_secret" => browser_secret,
                                  "configuration_id" => configuration_id, "purpose" => purpose.to_s, "remember" => remember == true}
        end

        def self.text?(value)
          value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, 2048) && !value.match?(/[\x00-\x1f\x7f]/)
        end
        private_class_method :text?

        def initialize(app, key:, lifetime: 600, clock: -> { Time.now })
          raise ArgumentError, "Apple callback key must be 32 bytes" unless key.is_a?(String) && key.bytesize == 32
          raise ArgumentError, "Apple callback lifetime must be positive" unless lifetime.is_a?(Integer) && lifetime.positive?

          @app = app
          @cipher = ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm", serializer: :json)
          @lifetime, @clock = lifetime, clock
        end

        def call(env)
          request = Rack::Request.new(env)
          return request.post? ? start(env) : @app.call(env) if request.path_info == START_PATH
          return callback(env, request) if request.path_info == CALLBACK_PATH

          @app.call(env)
        end

        private

        def start(env)
          pending = env.fetch("rack.session", {}).delete(PENDING_KEY)
          return @app.call(env) if pending.nil?
          return failure unless pending.is_a?(Hash) && valid_pending?(pending)

          status, headers, body = @app.call(env)
          return [status, headers, body] unless status.between?(300, 399)

          payload = pending.merge("state" => env.fetch("rack.session", {})["omniauth.state"],
            "nonce" => env.fetch("rack.session", {})["omniauth.nonce"])
          return [status, headers, body] unless valid_payload?(payload)

          write_cookie(headers, encrypt(payload))
          [status, headers, body]
        end

        def callback(env, request)
          # Do not claim a host-owned Apple callback without our capsule. A
          # request reaching AddAuth's controller still needs valid correlation.
          return @app.call(env) unless request.cookies.key?(COOKIE)
          payload = decrypt(request.cookies[COOKIE])
          return failure unless valid_payload?(payload)

          session = env.fetch("rack.session", {})
          session["omniauth.state"] = payload.fetch("state")
          session["omniauth.nonce"] = payload.fetch("nonce")
          env["add_auth.apple_correlation"] = payload.slice("transaction", "browser_secret", "configuration_id", "purpose", "remember")
          status, headers, body = @app.call(env)
          clear_cookie(headers)
          [status, headers, body]
        end

        def valid_pending?(payload)
          self.class.send(:text?, payload["transaction"]) && self.class.send(:text?, payload["browser_secret"]) &&
            self.class.send(:text?, payload["configuration_id"]) && self.class.send(:text?, payload["purpose"]) &&
            [true, false].include?(payload["remember"])
        end

        def valid_payload?(payload)
          payload.is_a?(Hash) && valid_pending?(payload) && self.class.send(:text?, payload["state"]) && self.class.send(:text?, payload["nonce"])
        end

        def encrypt(payload)
          @cipher.encrypt_and_sign(payload, purpose: PURPOSE, expires_in: @lifetime)
        end

        def decrypt(value)
          return unless self.class.send(:text?, value)

          @cipher.decrypt_and_verify(value, purpose: PURPOSE)
        rescue ActiveSupport::MessageEncryptor::InvalidMessage
          nil
        end

        def write_cookie(headers, value)
          Rack::Utils.set_cookie_header!(headers, COOKIE, value: value, path: CALLBACK_PATH, secure: true,
            httponly: true, same_site: :none, max_age: @lifetime)
        end

        def clear_cookie(headers)
          Rack::Utils.set_cookie_header!(headers, COOKIE, value: "", path: CALLBACK_PATH, secure: true,
            httponly: true, same_site: :none, max_age: 0)
        end

        def failure
          [422, {"content-type" => "text/plain", "cache-control" => "no-store"}, ["Provider sign-in could not be verified."]]
        end
      end
    end
  end
end
