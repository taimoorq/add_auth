# frozen_string_literal: true

require "add_auth/rails/rate_limit_cache"

require "uri"
require "add_auth/rails/stores/sessions"
require "add_auth/rails/stores/email_tokens"
require "add_auth/rails/delivery_cipher"

module AddAuth
  module Rails
    module Runtime
      module_function

      def config = AddAuth.configuration

      def sessions
        Core::Sessions.new(store: Stores::Sessions.new(user_model: ::User, session_model: ::Session),
          digest: config.session_token_digest, eligible: config.eligible, lifetime: config.session.lifetime,
          idle_timeout: config.session.idle_timeout, legacy_bridge_until: config.session.legacy_bridge_until, access_policy: access_policy)
      end

      def security_events
        raise AddAuth::Error, "enable notifications first" unless config.notifications.enabled
        require "add_auth/rails/stores/security_events"
        Core::SecurityEvents.new(store: Stores::SecurityEvents.new(user_model: ::User, event_model: ::AddAuthSecurityEvent),
          digest: config.sign_in_token_digest, delivery_cipher: DeliveryCipher.new(key: key("security-notifications")))
      end

      def access_policy
        Core::AccessPolicy.new(credentials: ->(id) {
          ::AddAuthCredential.find_by(external_id: id) if defined?(::AddAuthCredential) && ::AddAuthCredential.table_exists?
        }, passkeys_enabled: config.passkeys.enabled, email_enabled: Core::Intake.email_available?(config),
          trusted_recovery_address: config.trusted_recovery_address, password_enabled: config.passwords_enabled)
      end

      def email(purpose: :sign_in)
        if purpose.to_s != "sign_in" && !config.step_up.enabled
          raise AddAuth::Error, "enable step_up first"
        end
        raise AddAuth::Error, "enable session_upgrade and email_link first" unless Core::Intake.email_available?(config)
        Core::Strategies::EmailLink.new(store: Stores::EmailTokens.new(user_model: ::User,
          token_model: ::AddAuthSignInToken, session_model: ::Session), digest: config.sign_in_token_digest,
          delivery_cipher: DeliveryCipher.new(key: key("delivery")), eligible: config.eligible,
          normalize_identifier: method(:normalize), identifier_for: ->(user) { user.email_address },
          token_lifetime: {"reauthentication" => 300, "recovery" => 1200}.fetch(purpose.to_s, config.email_link.token_lifetime),
          same_browser: (purpose.to_s == "recovery") ? false : config.email_link.same_browser, purpose: purpose,
          proof_allowed: ->(user) { (purpose.to_s == "recovery") ? access_policy.recoverable?(user) && config.passkeys.enabled : purpose.to_s != "sign_in" || access_policy.sign_in_allowed?(user, :email_link) },
          sessions: (purpose.to_s == "sign_in") ? nil : sessions,
          policy: (purpose.to_s == "sign_in") ? nil : step_up_policy)
      end

      def revoke_all(user:, session:, **proof)
        policy = step_up_policy
        current = sessions.with_elevation(user: user, session: session, purpose: :sign_out_everywhere, policy: policy)
        if current.success?
          count = sessions.revoke_all(user: user, session: session, grant: current.credential)
          return count ? Result.success(user: user, strategy: :step_up) : Result.failure(reason: :elevation_required)
        end
        authorization = reauthenticate(user: user, session: session, **proof)
        return authorization unless authorization.success?
        count = sessions.revoke_all(user: user, session: session, grant: authorization.credential)
        count ? Result.success(user: user, strategy: :step_up) : Result.failure(reason: :elevation_required)
      end

      def reauthenticate(user:, session:, password:, ip:, challenge_token:)
        admitted = intake.call(identifier: user.email_address, ip: ip, action: :reauthenticate, challenge_token: challenge_token)
        return Result.failure(reason: admitted) if admitted.is_a?(Symbol)
        policy = config.step_up.enabled ? step_up_policy : Core::StepUp.new(purposes: {sign_out_everywhere: {methods: [:password]}})
        sessions.reauthenticate(user: user, session: session, purpose: :sign_out_everywhere, policy: policy) do |account|
          authenticate_password(identifier: account.email_address, password: password)
        end
      end

      def step_up_purposes
        defaults = if config.passkeys.enabled
          {
            manage_passkeys: {methods: [:password, :email_link, :passkey], return_to: "/passkeys", label: "manage your passkeys"},
            manage_policy: {methods: [:passkey], require_passkey: true, return_to: "/passkeys", label: "change your recovery policy"},
            recover_passkeys: {methods: [:email_link], return_to: "/passkeys", label: "replace a lost passkey", reauthentication: false}
          }
        else
          {}
        end
        {sign_out_everywhere: {methods: [:password, :email_link, :passkey], return_to: "/sessions/revoke-all", label: "sign out everywhere"}}.merge(defaults).merge(config.step_up.purposes)
      end

      def passkeys
        raise AddAuth::Error, "enable passkeys and their prerequisites first" unless config.passkeys.enabled && config.step_up.enabled && config.notifications.enabled
        require "add_auth/rails/stores/passkeys"
        Core::Strategies::Passkey.new(store: Stores::Passkeys.new(user_model: ::User, session_model: ::Session,
          credential_model: ::AddAuthCredential, ceremony_model: ::AddAuthCeremony, token_model: ::AddAuthSignInToken), sessions: sessions,
          policy: step_up_policy, access_policy: access_policy, digest: config.sign_in_token_digest,
          eligible: config.eligible, rp_id: config.passkeys.rp_id, origins: config.passkeys.origins, name: config.passkeys.name,
          limiter: method(:limit), anonymous_limit: config.passkeys.anonymous_limit,
          notify: ->(**event) { security_events.issue(**event) }, allow_localhost: !::Rails.env.production?, support_url: config.support_url,
          on_failure: ->(reason) { ::ActiveSupport::Notifications.instrument("passkey_failure.add_auth", reason: reason) })
      end

      def step_up_policy
        Core::StepUp.new(purposes: config.step_up.enabled ? step_up_purposes : {}, fresh_for: config.step_up.fresh_for,
          strong_for: config.step_up.strong_for,
          password_version: ->(user) { config.sign_in_token_digest.digest("password:#{user.password_digest}") },
          credential_current: ->(user:, evidence:) {
            evidence.method == :password ||
              (evidence.method == :passkey && access_policy.credential_current?(user: user, id: evidence.credential_id) &&
                ::AddAuthCredential.find_by(external_id: evidence.credential_id)&.public_key == evidence.credential_version) ||
              (evidence.method == :email_link && Core::Intake.email_available?(config) &&
              config.sign_in_token_digest.matches?(evidence.credential_version, "identifier:#{normalize(user.email_address)}"))
          }, methods_available: ->(user) { access_policy.methods_for(user) })
      end

      def elevate_password(user:, session:, purpose:, password:, ip:, challenge_token:)
        return Result.failure(reason: :elevation_required) unless step_up_policy.reauthentication_rule_for(purpose)
        admitted = intake.call(identifier: user.email_address, ip: ip, action: :reauthenticate, challenge_token: challenge_token)
        return Result.failure(reason: admitted) if admitted.is_a?(Symbol)
        proof = sessions.reauthenticate(user: user, session: session, purpose: purpose, policy: step_up_policy) do |account|
          authenticate_password(identifier: account.email_address, password: password)
        end
        return proof unless proof.success?
        grant = sessions.rotate_for_step_up(user: user, session: session, grant: proof.credential)
        grant ? Result.success(user: user, strategy: :step_up, session: grant.session, credential: grant) : Result.failure(reason: :elevation_required)
      end

      def enqueue_recovery(identifier) = enqueue_email_payload({identifier: identifier, purpose: "recovery"})

      def enqueue_reauthentication(user:, session:, purpose:, browser_secret:)
        payload = {identifier: user.email_address, purpose: "reauthentication", authentication_purpose: purpose.to_s,
                   session_id: session.id, session_digest: session.token_digest, browser_digest: browser_binding.digest(browser_secret)}
        enqueue_email_payload(payload)
      end

      def authenticate_password(identifier:, password:)
        return unless config.passwords_enabled && ::User.respond_to?(:authenticate_by)
        ::User.authenticate_by(email_address: identifier, password: password.is_a?(String) ? password : "")
      end

      def sign_in_path = "/sign-in"

      def normalize(value) = ::User.normalize_value_for(:email_address, value)
      def key(purpose) = ::Rails.application.key_generator.generate_key("add_auth.#{purpose}.v1", 32)

      def intake_cipher
        ActiveSupport::MessageEncryptor.new(key("intake"), cipher: "aes-256-gcm", serializer: :json)
      end

      def browser_binding = Core::BrowserBinding.new(digest: config.sign_in_token_digest)

      def enqueue_email(identifier, browser_secret: nil)
        payload = {identifier: identifier, browser_digest: email.browser_digest(browser_secret)}
        enqueue_email_payload(payload)
      end

      def enqueue_email_payload(payload)
        job = ::AddAuth::EmailRequestJob.perform_later(encrypt_intake(payload))
        raise AddAuth::Error, "sign-in queue unavailable" unless job
        job
      rescue
        raise AddAuth::Error, "sign-in queue unavailable", cause: nil
      end

      def encrypt_intake(identifier)
        intake_cipher.encrypt_and_sign(identifier, purpose: "sign_in_request", expires_in: 300)
      end

      def decrypt_intake(payload)
        intake_cipher.decrypt_and_verify(payload, purpose: "sign_in_request")
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        nil
      end

      def intake
        Core::Intake.new(digest: config.sign_in_token_digest, normalizer: method(:normalize),
          limiter: method(:limit), challenge: config.challenge, challenge_on: config.challenge_on,
          challenge_when_unavailable: config.challenge_when_unavailable,
          on_challenge_unavailable: method(:record_challenge_bypass))
      end

      def record_challenge_bypass(action:)
        ::ActiveSupport::Notifications.instrument("challenge_bypass.add_auth", action: action)
      end

      def limit(key:, limit:)
        Core::RateLimit.new(counter: ->(key:, expires_in:) {
          rate_limit_cache.increment(key, 1, expires_in: expires_in, initial: 0)
        }).call(key: key, limit: limit)
      rescue
        raise AddAuth::Error, "rate limit store unavailable", cause: nil
      end

      def rate_limit_cache = RateLimitCache.validate!(config.rate_limit_store || ::Rails.cache)

      def maintenance_cache_key = "add_auth:maintenance:v1:#{config.sign_in_token_digest.digest("last-success")}"

      def record_maintenance
        unless rate_limit_cache.write(maintenance_cache_key, Time.now.to_i, expires_in: 180)
          raise AddAuth::Error, "maintenance heartbeat store unavailable"
        end
      end

      def maintenance_current?
        completed = rate_limit_cache.read(maintenance_cache_key)
        completed.is_a?(Integer) && (0..120).cover?(Time.now.to_i - completed)
      end

      def sign_in_url(token, purpose: "sign_in")
        uri = URI.parse(config.base_url.to_s)
        valid = uri.host && !uri.userinfo && !uri.query && !uri.fragment && ["", "/"].include?(uri.path) &&
          (uri.scheme == "https" || (!::Rails.env.production? && uri.scheme == "http"))
        unless valid
          raise AddAuth::Error, "configure base_url as a fixed HTTPS origin (HTTP allowed only outside production)"
        end
        path = {"sign_in" => "/sign-in/link", "reauthentication" => "/reauthenticate/link", "recovery" => "/recover/link"}.fetch(purpose.to_s)
        "#{uri.to_s.delete_suffix("/")}#{path}?token=#{URI.encode_www_form_component(token)}"
      end
    end
  end
end
