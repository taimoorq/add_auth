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

      def account_policy
        Core::AccountPolicy.new(enabled: config.lifecycle.enabled, eligible: config.lifecycle.eligible)
      end

      def eligible(user)
        config.eligible.call(user) == true && account_policy.allowed?(user)
      end

      def authority
        require "add_auth/rails/stores/authority"
        tokens = []
        tokens << ::AddAuthSignInToken if defined?(::AddAuthSignInToken) && ::AddAuthSignInToken.table_exists?
        tokens << ::AddAuthAccountToken if defined?(::AddAuthAccountToken) && ::AddAuthAccountToken.table_exists?
        ceremonies = []
        ceremonies << ::AddAuthCeremony if defined?(::AddAuthCeremony) && ::AddAuthCeremony.table_exists?
        ceremonies << ::AddAuthExternalTransaction if defined?(::AddAuthExternalTransaction) && ::AddAuthExternalTransaction.table_exists?
        ceremonies << ::AddAuthMobileHandoff if defined?(::AddAuthMobileHandoff) && ::AddAuthMobileHandoff.table_exists?
        invalidator = if defined?(::AddAuthExternalIdentity) && ::AddAuthExternalIdentity.table_exists?
          ->(user_id:, at:) { Core::ExternalIdentities.invalidate_credentials_in_transaction(store: external_identity_store, user_id: user_id, at: at) }
        end
        Stores::Authority.new(user_model: ::User, session_model: ::Session, token_models: tokens, ceremony_models: ceremonies, external_invalidator: invalidator)
      end

      def external_identity_store
        require "add_auth/rails/stores/external_identities"
        Stores::ExternalIdentities.new(user_model: ::User, identity_model: ::AddAuthExternalIdentity, transaction_model: ::AddAuthExternalTransaction)
      end

      def external_provider(id)
        config.external_identities.provider(id) if config.external_identities.enabled
      end

      def external_reauthentication? = config.external_identities.enabled && config.external_identities.providers.any?(&:reauthentication?)

      def external_identities
        options = config.external_identities
        raise AddAuth::Error, "enable external identities and register a provider first" unless options.enabled && options.configurations.any?
        Core::ExternalIdentities.new(store: external_identity_store, configurations: options.configurations,
          sessions: sessions, access_policy: access_policy, policy: step_up_policy, eligible: method(:eligible),
          digest: config.sign_in_token_digest, revoke_authority: authority.method(:revoke),
          remaining_method: remaining_factors,
          enrollment_eligible: ->(user) { account_policy.allowed?(user, purpose: :confirm) }, enabled: true, mobile_enabled: config.mobile.enabled)
      end

      def remaining_factors
        require "add_auth/core/remaining_factors"
        require "add_auth/core/passwords/credential"
        credential = Core::Passwords::Credential.new(legacy_verifier: config.legacy_password_verifier)
        Core::RemainingFactors.new(access_policy: access_policy,
          passkey_count: ->(user) { (defined?(::AddAuthCredential) && ::AddAuthCredential.table_exists?) ? ::AddAuthCredential.where(user_id: user.id, revoked_at: nil).count : 0 },
          password_available: ->(user) { credential.available?(user: user, current: config.current_password_support) })
      end

      def provider_enrollment
        require "add_auth/rails/provider_enrollment"
        ProviderEnrollment.new(model: ::AddAuthExternalTransaction, digest: config.sign_in_token_digest, key: key("external-enrollment"))
      end

      def accounts
        raise AddAuth::Error, "enable account lifecycle first" unless config.lifecycle.enabled
        require "add_auth/rails/stores/account_tokens"
        Core::AccountLifecycle.new(store: Stores::AccountTokens.new(user_model: ::User, token_model: ::AddAuthAccountToken,
          session_model: ::Session, address_model: ::AddAuthAddressClaim, authority: authority, provision: config.lifecycle.provision, delete_account: config.lifecycle.delete_account),
          digest: config.sign_in_token_digest, delivery_cipher: DeliveryCipher.new(key: key("account-proofs")),
          policy: account_policy, password_policy: config.lifecycle.password_policy, trusted_address: config.trusted_recovery_address,
          lifetime: config.lifecycle.proof_lifetime, notify: ->(**event) { security_events.issue(**event) if config.notifications.enabled },
          sessions: sessions, step_up_policy: step_up_policy, profile_attributes: config.lifecycle.profile_attributes, deletion_allowed: config.lifecycle.deletion_allowed,
          external_identities: -> { external_identities })
      end

      def enqueue_account_request(identifier:, purpose:)
        job = ::AddAuth::AccountRequestJob.perform_later(encrypt_intake(identifier: identifier, purpose: purpose))
        raise AddAuth::Error, "account request queue unavailable" unless job
        job
      rescue
        raise AddAuth::Error, "account request queue unavailable", cause: nil
      end

      def account_proof_url(token, purpose:)
        raise AddAuth::Error, "unsupported account proof" unless Core::AccountLifecycle::PURPOSES.include?(purpose)
        authentication_url("/account/proofs/#{purpose}", token: token)
      end

      def sessions
        Core::Sessions.new(store: Stores::Sessions.new(user_model: ::User, session_model: ::Session),
          digest: config.session_token_digest, eligible: method(:eligible), lifetime: config.session.lifetime,
          idle_timeout: config.session.idle_timeout, legacy_bridge_until: config.session.legacy_bridge_until, access_policy: access_policy,
          password_lifecycle: password_lifecycle,
          mobile_profile: mobile_profile,
          verified_denial: ->(user) { (config.eligible.call(user) == true) ? account_policy.denial(user) : :disabled },
          remembered_profile: config.lifecycle.enabled ? {lifetime: config.lifecycle.remember_lifetime, idle_timeout: config.lifecycle.remember_idle_timeout} : nil,
          on_sign_in: method(:record_sign_in))
      end

      def mobile_profile
        options = config.mobile
        return unless options.enabled
        raise AddAuth::Error, "enable session_upgrade before mobile sessions" unless config.session.enabled
        Core::MobileProfile.new(lifetime: options.lifetime, idle_timeout: options.idle_timeout, clients: options.clients, callbacks: options.callbacks)
      end

      def mobile_authentication
        require "add_auth/core/mobile_authentication"
        Core::MobileAuthentication.new(sessions: sessions, profile: mobile_profile,
          intake: intake, verify_password: method(:authenticate_password))
      end

      def mobile_handoffs
        require "add_auth/core/mobile_handoffs"
        require "add_auth/rails/stores/mobile_handoffs"
        Core::MobileHandoffs.new(store: Stores::MobileHandoffs.new(user_model: ::User, handoff_model: ::AddAuthMobileHandoff, session_model: ::Session),
          profile: mobile_profile, sessions: sessions, access_policy: access_policy, digest: config.sign_in_token_digest)
      end

      def native_apple
        require "add_auth/core/native_authentication"
        require "add_auth/rails/provider_libraries/apple_native"
        require "add_auth/rails/provider_libraries/apple_jwks"
        raise AddAuth::Error, "install and require ruby-jwt for native Apple authentication" unless defined?(::JWT)
        raise AddAuth::Error, "configure native Apple providers as an explicit client map" unless config.mobile.apple_providers.is_a?(Hash)
        providers = config.mobile.apple_providers.transform_values { |id| config.external_identities.native_provider(id) }
        Core::NativeAuthentication.new(external_identities: external_identities, profile: mobile_profile,
          providers: providers, intake: intake, accounts: (method(:accounts) if config.lifecycle.enabled), verify: ->(**arguments) {
            ProviderLibraries::AppleNative::CallbackResult.capture(**arguments, jwks: ProviderLibraries::AppleJwks.new(cache: ::Rails.cache))
          })
      end

      def record_sign_in(user:, session:, at:)
        require "add_auth/rails/stores/commit_dispatch"
        Stores::CommitDispatch.event(transaction: ::User.current_transaction, event: "session_created.add_auth",
          payload: {user_id: user.id, session_id: session.id, method: session.authenticated_with, occurred_at: at})
      end

      def password_lifecycle
        return unless config.lifecycle.enabled || ::User.column_names.include?("add_auth_password_scheme")
        require "add_auth/core/passwords/lifecycle"
        require "add_auth/rails/stores/account_credentials"
        Core::Passwords::Lifecycle.new(store: Stores::AccountCredentials.new(user_model: ::User, authority: authority),
          policy: method(:eligible), enabled: config.lifecycle.enabled,
          maximum_attempts: config.lifecycle.maximum_attempts, unlock_in: config.lifecycle.unlock_in,
          issue_unlock: ->(user) { accounts.issue_unlock_in_transaction(user: user) })
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
          trusted_recovery_address: config.trusted_recovery_address, password_enabled: config.passwords_enabled,
          external_enabled: config.external_identities.enabled,
          external_current: ->(**arguments) { external_identities.credential_current?(**arguments) })
      end

      def email(purpose: :sign_in)
        if purpose.to_s != "sign_in" && !config.step_up.enabled
          raise AddAuth::Error, "enable step_up first"
        end
        raise AddAuth::Error, "enable session_upgrade and email_link first" unless Core::Intake.email_available?(config)
        Core::Strategies::EmailLink.new(store: Stores::EmailTokens.new(user_model: ::User,
          token_model: ::AddAuthSignInToken, session_model: ::Session), digest: config.sign_in_token_digest,
          delivery_cipher: DeliveryCipher.new(key: key("delivery")), eligible: method(:eligible),
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
        if config.lifecycle.enabled
          defaults = defaults.merge(
            change_email: {methods: [:password, :email_link, :passkey], return_to: "/account/email", label: "change your email address"},
            change_password: {methods: [:password, :email_link, :passkey], return_to: "/account/password", label: "change your password"},
            delete_account: {methods: [:password, :email_link, :passkey], return_to: "/account/delete", label: "delete your account"}
          )
        end
        if config.external_identities.enabled
          defaults = defaults.merge(
            link_external_identity: {methods: [:password, :email_link, :passkey], return_to: "/account/external-identities", label: "link a sign-in provider"},
            unlink_external_identity: {methods: [:password, :email_link, :passkey], return_to: "/account/external-identities", label: "remove a sign-in provider"}
          )
          defaults = defaults.transform_values do |rule|
            (!external_reauthentication? || rule[:require_passkey] || rule[:reauthentication] == false) ? rule : rule.merge(methods: (rule[:methods] + [:external_identity]).uniq)
          end
        end
        {sign_out_everywhere: {methods: [:password, :email_link, :passkey, *(:external_identity if external_reauthentication?)], return_to: "/sessions/revoke-all", label: "sign out everywhere"}}.merge(defaults).merge(config.step_up.purposes)
      end

      def passkeys
        raise AddAuth::Error, "enable passkeys and their prerequisites first" unless config.passkeys.enabled && config.step_up.enabled && config.notifications.enabled
        require "add_auth/rails/stores/passkeys"
        Core::Strategies::Passkey.new(store: Stores::Passkeys.new(user_model: ::User, session_model: ::Session,
          credential_model: ::AddAuthCredential, ceremony_model: ::AddAuthCeremony, token_model: ::AddAuthSignInToken), sessions: sessions,
          policy: step_up_policy, access_policy: access_policy, digest: config.sign_in_token_digest,
          eligible: method(:eligible), rp_id: config.passkeys.rp_id, origins: config.passkeys.origins, name: config.passkeys.name,
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
              (evidence.method == :external_identity && access_policy.external_credential_current?(user: user, id: evidence.credential_id, version: evidence.credential_version)) ||
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
        path = {"sign_in" => "/sign-in/link", "reauthentication" => "/reauthenticate/link", "recovery" => "/recover/link"}.fetch(purpose.to_s)
        authentication_url(path, token: token)
      end

      def authentication_url(path, **query)
        uri = URI.parse(config.base_url.to_s)
        valid = uri.host && !uri.userinfo && !uri.query && !uri.fragment && ["", "/"].include?(uri.path) &&
          (uri.scheme == "https" || (!::Rails.env.production? && uri.scheme == "http"))
        unless valid
          raise AddAuth::Error, "configure base_url as a fixed HTTPS origin (HTTP allowed only outside production)"
        end
        "#{uri.to_s.delete_suffix("/")}#{path}?#{URI.encode_www_form(query)}"
      rescue URI::InvalidURIError
        raise AddAuth::Error, "configure a fixed HTTPS origin", cause: nil
      end
    end
  end
end
