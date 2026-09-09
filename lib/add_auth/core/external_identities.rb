# frozen_string_literal: true

require "add_auth/core/external_identities/evidence"
require "securerandom"

module AddAuth
  module Core
    class ExternalIdentities
      LINK = :link_external_identity
      UNLINK = :unlink_external_identity
      ENROLL = :enroll_external_identity
      MOBILE = :mobile_sign_in
      NATIVE = :native_sign_in
      NATIVE_ENROLL = :native_enroll_external_identity
      ENROLLMENT_PURPOSES = [ENROLL, NATIVE_ENROLL].freeze

      # G3 rescues this outside its fresh-account transaction. Returning a
      # failure Result here would commit a partially registered account.
      class EnrollmentRejected < StandardError
        attr_reader :reason
        def initialize(reason:)
          @reason = reason
          super("external identity enrollment rejected")
        end
      end

      # remaining_method is a Core policy port evaluated under the account lock;
      # it must check actual enabled/usable password, passkey or trusted recovery
      # credentials. Authority invalidation uses the shared lifecycle transaction.
      def initialize(store:, configurations:, sessions:, access_policy:, policy:, eligible:,
        digest:, revoke_authority:, remaining_method:, enrollment_eligible: ->(_user) { false }, clock: Time, lifetime: 300, enabled: false, mobile_enabled: false)
        raise ArgumentError, "invalid transaction lifetime" unless lifetime.is_a?(Integer) && lifetime.between?(1, 600)
        @store, @sessions, @access, @policy, @eligible = store, sessions, access_policy, policy, eligible
        @configurations = configurations.to_h { |config| [config.id, config] }.freeze
        raise ArgumentError, "duplicate provider configuration" unless @configurations.size == configurations.size
        @digest, @revoke, @remaining, @clock, @lifetime, @enabled = digest, revoke_authority, remaining_method, clock, lifetime, enabled == true
        @enrollment_eligible = enrollment_eligible
        @mobile_enabled = mobile_enabled == true
        @binding = BrowserBinding.new(digest: digest)
      end

      def begin_transaction(configuration_id:, browser_secret:, user: nil, session: nil, purpose: :sign_in, binding_context: nil)
        return failure(:disabled) unless @enabled
        config = @configurations[configuration_id]
        return failure unless config && @binding.valid?(browser_secret) && valid_context?(binding_context)
        return failure(:disabled) if [MOBILE.to_s, NATIVE.to_s, NATIVE_ENROLL.to_s].include?(purpose.to_s) && !@mobile_enabled
        if ["sign_in", ENROLL.to_s, MOBILE.to_s, NATIVE.to_s, NATIVE_ENROLL.to_s].include?(purpose.to_s)
          return failure if user || session
          return issue(config, browser_secret, purpose, binding_context: binding_context)
        end
        @store.with_user(id: user&.id) do |account|
          row = account && @sessions.current_in_transaction(user: account, session: session)
          allowed = purpose.to_s == LINK.to_s || @policy.reauthentication_rule_for(purpose)
          next failure(:elevation_required) unless row && @eligible.call(account) == true && allowed
          issue(config, browser_secret, purpose, account, row, binding_context: binding_context)
        end
      end

      def pending(transaction:, browser_secret:, binding_context: nil)
        return unless @enabled && @binding.valid?(transaction) && @binding.valid?(browser_secret) && valid_context?(binding_context)
        row = @store.transaction_by_digest(digest: @digest.digest(transaction))
        return unless row && row.browser_digest == binding_digest(browser_secret, binding_context) && !row.consumed_at &&
          row.expires_at > @clock.now && row.issued_at <= @clock.now
        config = @configurations[row.provider_id]
        return unless config && row.issuer == config.issuer && row.audience == config.audience
        Pending.send(:new, configuration: config, id: transaction, purpose: row.purpose,
          user_id: row.user_id, session_id: row.session_id, session_digest: row.session_digest,
          policy_version: row.policy_version, issued_at: row.issued_at, expires_at: row.expires_at)
      end

      # Cancellation is correlation-bound, idempotent and grants no authority.
      def cancel(transaction:, browser_secret:, binding_context: nil)
        proof = pending(transaction: transaction, browser_secret: browser_secret, binding_context: binding_context)
        return false unless proof
        @store.consume_transaction(digest: @digest.digest(proof.id), at: @clock.now)
      end

      def sign_in(evidence:, replacing: nil, **hints)
        finalize_sign_in(evidence: evidence, purpose: :sign_in, replacing: replacing) do |account, identity, proof|
          grant = @sessions.create_in_transaction(user: account, method: :external_identity,
            proof: proof, replacing: replacing, **hints)
          raise AddAuth::Error, "external identity session could not finalize" unless grant
          Result.success(user: account, strategy: :external_identity, credential: identity, session: grant.session, grant: grant)
        end
      end

      def mobile_handoff(evidence:, handoffs:)
        return failure(:disabled) unless @mobile_enabled
        finalize_sign_in(evidence: evidence, purpose: MOBILE) do |account, _identity, proof|
          handoffs.issue_in_transaction(user: account, proof: proof, pending: evidence.transaction)
        end
      end

      def native_sign_in(evidence:, client_id:, **hints)
        return failure(:disabled) unless @mobile_enabled
        finalize_sign_in(evidence: evidence, purpose: NATIVE) do |account, identity, proof|
          grant = @sessions.create_in_transaction(user: account, method: :external_identity,
            proof: proof, transport: :mobile, client_id: client_id, **hints)
          raise AddAuth::Error, "native identity session could not finalize" unless grant
          Result.success(user: account, strategy: :external_identity, credential: identity, session: grant.session, grant: grant)
        end
      end

      def link(user:, session:, evidence:, grant:)
        return failure(:disabled) unless @enabled
        return failure unless trusted?(evidence) && evidence.purpose == LINK
        @store.with_user(id: user&.id) do |account|
          next failure(:elevation_required) unless management?(account, session, grant, LINK) && bound?(evidence, account, session)
          finalize(evidence, account) do
            identity = @store.binding(namespace: evidence.namespace)
            if identity && (identity.user_id != account.id || !matches?(identity, evidence))
              next failure(:identity_conflict)
            end
            identity = @store.bind(user: account, evidence: evidence, at: @clock.now)
            next failure(:identity_conflict) unless identity
            Result.success(user: account, strategy: :external_identity, credential: identity)
          end
        end
      end

      # Registration capability is minted by G3 only in create_account's fresh
      # user block. This joins that transaction; it never authenticates the user.
      def bind_new_account_in_transaction(registration:, evidence:)
        reject_enrollment(:disabled) unless @enabled
        valid_registration = defined?(AccountLifecycle::NewAccount) && registration.instance_of?(AccountLifecycle::NewAccount)
        reject_enrollment unless valid_registration && trusted?(evidence) && ENROLLMENT_PURPOSES.include?(evidence.purpose)
        reject_enrollment(:disabled) if evidence.purpose == NATIVE_ENROLL && !@mobile_enabled
        tx = evidence.transaction
        reject_enrollment unless tx.user_id.nil? && tx.session_id.nil? && tx.session_digest.nil? && tx.policy_version.nil?
        account = @store.registration_account(user: registration.user)
        reject_enrollment unless account && account.id == registration.user_id && @enrollment_eligible.call(account) == true
        reject_enrollment(:expired_token) unless tx.issued_at <= @clock.now && tx.expires_at > @clock.now
        reject_enrollment(:identity_conflict) if @store.binding(namespace: evidence.namespace)
        reject_enrollment(:consumed_token) unless @store.consume_transaction(digest: @digest.digest(tx.id), at: @clock.now)
        identity = @store.bind(user: account, evidence: evidence, at: @clock.now)
        reject_enrollment(:identity_conflict) unless identity
        Result.success(user: account, strategy: :external_identity, credential: identity)
      end

      def unlink(user:, session:, identity_id:, grant:)
        return failure(:disabled) unless @enabled
        @store.with_user(id: user&.id) do |account|
          next failure(:elevation_required) unless management?(account, session, grant, UNLINK)
          identity = @store.binding_for_user(user_id: account.id, id: identity_id)
          next failure unless identity && !identity.revoked_at
          remaining = @store.bindings(user_id: account.id).any? { |other| other.id != identity.id && configured?(other) } &&
            @access.sign_in_allowed?(account, :external_identity)
          next failure(:last_credential) unless remaining || @remaining.call(account) == true
          @store.revoke(identity: identity, at: @clock.now)
          @revoke.call(user_id: account.id, at: @clock.now)
          Result.success(user: account, strategy: :external_identity)
        end
      end

      def reauthenticate(user:, session:, evidence:, policy: @policy)
        return failure(:disabled) unless @enabled
        return failure(:elevation_required) unless trusted?(evidence) && ![:sign_in, LINK, ENROLL].include?(evidence.purpose)
        @store.with_user(id: user&.id) do |account|
          row = account && @sessions.current_in_transaction(user: account, session: session)
          next failure(:elevation_required) unless row && @eligible.call(account) == true && bound?(evidence, account, row) &&
            @access.sign_in_allowed?(account, :external_identity)
          identity = @store.binding(namespace: evidence.namespace)
          next failure unless current_identity?(identity, evidence) && identity.user_id == account.id
          # A callback timestamp is never substituted for provider auth_time.
          time = evidence.authenticated_at
          next failure(:elevation_required) unless time && time >= Time.at(evidence.transaction.issued_at.to_i) && time <= @clock.now
          proof = StepUp::ExternalEvidence.send(:new, user_id: account.id, session_id: row.id,
            method: :external_identity, verified_at: time, credential_id: identity.id.to_s,
            credential_version: identity.credential_version, session_digest: row.token_digest, purpose: evidence.purpose)
          authorized = policy.authorize(user: account, session_id: row.id, purpose: evidence.purpose, evidence: proof)
          next authorized unless authorized.success?
          finalize(evidence, account) { authorized }
        end
      end

      # Called by the shared authority-revocation transaction even while provider
      # sign-in is disabled. A binding survives the event, but older anonymous
      # transactions and previously issued session/elevation proofs do not.
      def self.invalidate_credentials_in_transaction(store:, user_id:, at:)
        raise ArgumentError, "invalidation requires an occurrence time" unless at.is_a?(Time)
        store.invalidate_credentials(user_id: user_id, at: at, credential_version: SecureRandom.hex(16))
      end

      def invalidate_credentials_in_transaction(user_id:, at:)
        self.class.invalidate_credentials_in_transaction(store: @store, user_id: user_id, at: at)
      end

      def credential_current?(user:, id:, version:)
        return false unless @enabled
        identity = @store.binding_for_user(user_id: user.id, id: id)
        !!(identity && !identity.revoked_at && identity.credential_version == version && configured?(identity))
      end

      private

      def finalize_sign_in(evidence:, purpose:, replacing: nil)
        return failure(:disabled) unless @enabled
        return failure unless trusted?(evidence) && evidence.purpose == purpose
        @store.with_identity(namespace: evidence.namespace, replacing: replacing) do |account, identity|
          next failure(:identity_unbound) unless bound_identity?(identity, evidence)
          next failure unless current_identity?(identity, evidence)
          next failure unless account && @eligible.call(account) == true && @access.sign_in_allowed?(account, :external_identity)
          finalize(evidence, account) do
            proof = SessionProof.send(:new, user_id: account.id, credential_id: identity.id,
              credential_version: identity.credential_version, verified_at: @clock.now)
            yield account, identity, proof
          end
        end
      end

      def issue(config, browser_secret, purpose, account = nil, session = nil, binding_context: nil)
        raw = @binding.generate
        now = @clock.now
        @store.create_transaction(digest: @digest.digest(raw), browser_digest: binding_digest(browser_secret, binding_context),
          provider_id: config.id, issuer: config.issuer, audience: config.audience, purpose: purpose.to_s,
          user_id: account&.id, session_id: session&.id, session_digest: session&.token_digest,
          policy_version: account && @access.version(account), issued_at: now, expires_at: now + @lifetime)
        Result.success(user: account, strategy: :external_identity, credential: pending(transaction: raw, browser_secret: browser_secret, binding_context: binding_context))
      end

      def valid_context?(context)
        context.nil? || (context.is_a?(String) && context.ascii_only? && /\A[a-z][a-z0-9_:-]{0,127}\z/.match?(context))
      end

      def binding_digest(secret, context)
        @digest.digest(context ? JSON.generate(["context", context, secret]) : secret)
      end

      def trusted?(evidence)
        evidence.is_a?(VerifiedIdentity) && @configurations[evidence.provider_id].equal?(evidence.configuration)
      end

      def configured?(identity)
        config = @configurations[identity.provider_id]
        config && config.issuer == identity.issuer && config.audience == identity.audience
      end

      def matches?(identity, evidence)
        identity.provider_id == evidence.provider_id && identity.issuer == evidence.issuer &&
          identity.audience == evidence.audience && identity.subject == evidence.subject
      end

      def bound_identity?(identity, evidence) = identity && !identity.revoked_at && matches?(identity, evidence)

      def current_identity?(identity, evidence)
        bound_identity?(identity, evidence) && identity.linked_at <= evidence.transaction.issued_at &&
          (!identity.invalidated_at || evidence.transaction.issued_at > identity.invalidated_at)
      end

      def bound?(evidence, account, session)
        tx = evidence.transaction
        tx.user_id == account.id && tx.session_id == session.id && tx.session_digest == session.token_digest &&
          tx.policy_version == @access.version(account)
      end

      def management?(account, session, grant, purpose)
        row = account && @sessions.current_in_transaction(user: account, session: session)
        row && @eligible.call(account) == true && grant.is_a?(StepUp::Grant) &&
          grant.valid_for?(user: account, user_id: account.id, session_id: row.id,
            session_digest: row.token_digest, purpose: purpose, now: @clock.now)
      end

      def finalize(evidence, account)
        tx = evidence.transaction
        return failure(:expired_token) unless tx.issued_at <= @clock.now && tx.expires_at > @clock.now
        return failure unless @eligible.call(account) == true
        return failure(:consumed_token) unless @store.consume_transaction(digest: @digest.digest(tx.id), at: @clock.now)
        yield
      end

      def reject_enrollment(reason = :invalid_credentials)
        raise EnrollmentRejected.new(reason: reason)
      end

      def failure(reason = :invalid_credentials) = Result.failure(reason: reason)
    end
  end
end
