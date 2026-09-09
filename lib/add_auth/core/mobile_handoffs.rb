# frozen_string_literal: true

require "digest"
require "base64"

module AddAuth
  module Core
    # The native verifier protects this application handoff. It does not replace
    # upstream provider state/nonce/PKCE, which remain the library's responsibility.
    class MobileHandoffs
      PURPOSE = ExternalIdentities::MOBILE
      CODE = /\Aah1:[A-Za-z0-9_-]{43}\z/
      STATE = /\A[A-Za-z0-9_-]{43,128}\z/
      VERIFIER = /\A[A-Za-z0-9._~-]{43,128}\z/
      CHALLENGE = /\A[A-Za-z0-9_-]{43}\z/
      Handoff = Struct.new(:code, :state, :callback) do
        def inspect = "#<AddAuth::Core::MobileHandoffs::Handoff [FILTERED]>"
      end

      def initialize(store:, profile:, sessions:, access_policy:, digest:, clock: Time, lifetime: 60)
        raise ArgumentError, "handoff lifetime must be between 1 and 120 seconds" unless lifetime.is_a?(Integer) && lifetime.between?(1, 120)
        @store, @profile, @sessions, @access, @digest, @clock, @lifetime = store, profile, sessions, access_policy, digest, clock, lifetime
      end

      def begin_transaction(pending:, client_id:, callback:, state:, code_challenge:, code_challenge_method:)
        return failure unless pending.is_a?(ExternalIdentities::Pending) && pending.purpose == PURPOSE &&
          @profile&.client?(client_id) && @profile.callback(client_id) == callback && callback &&
          text?(state, STATE) && text?(code_challenge, CHALLENGE) && code_challenge_method == "S256" &&
          pending.issued_at <= @clock.now && pending.expires_at > @clock.now
        row = @store.create_pending(external_digest: @digest.digest(pending.id), client_id: client_id, callback: callback,
          state: state, challenge_digest: @digest.digest(code_challenge), issued_at: pending.issued_at, expires_at: pending.expires_at)
        row ? Result.success(user: nil, strategy: :external_identity) : failure
      end

      # Called only from ExternalIdentities' verified binding finalizer, inside
      # the owning account transaction. No Session or bearer exists at this point.
      def issue_in_transaction(user:, proof:, pending:)
        return failure unless proof.is_a?(ExternalIdentities::SessionProof) && proof.user_id == user.id && pending.purpose == PURPOSE
        row = @store.by_external_digest(digest: @digest.digest(pending.id))
        return failure unless row && current_profile?(row) && !row.digest && !row.consumed_at && row.expires_at > @clock.now
        code = "ah1:#{SecureRandom.urlsafe_base64(32)}"
        issued = @store.issue(row: row, user_id: user.id, digest: @digest.digest(code),
          credential_id: proof.credential_id, credential_version: proof.credential_version,
          policy_version: @access.version(user), authenticated_at: proof.verified_at,
          expires_at: [row.expires_at, @clock.now + @lifetime].min)
        return failure unless issued
        Result.success(user: user, strategy: :external_identity, credential: Handoff.new(code: code, state: row.state, callback: row.callback))
      end

      def exchange(code:, state:, code_verifier:, client_id:, ip: nil, user_agent: nil)
        return failure unless @profile&.client?(client_id) && text?(code, CODE) && text?(state, STATE) && text?(code_verifier, VERIFIER)
        challenge = Base64.urlsafe_encode64(::Digest::SHA256.digest(code_verifier), padding: false)
        @store.with_code(digest: @digest.digest(code)) do |user, row|
          now = @clock.now
          next failure unless user && row && current_profile?(row) && row.client_id == client_id &&
            @digest.matches?(row.challenge_digest, challenge) && @digest.matches?(@digest.digest(row.state), state)
          next failure(:consumed_token) if row.consumed_at
          next failure(:expired_token) unless row.issued_at <= now && row.expires_at > now
          next failure unless row.policy_version == @access.version(user)
          proof = ExternalIdentities::SessionProof.send(:new, user_id: user.id, credential_id: row.credential_id,
            credential_version: row.credential_version, verified_at: row.authenticated_at)
          grant = @sessions.create_in_transaction(user: user, method: :external_identity, proof: proof,
            transport: :mobile, client_id: row.client_id, ip_address: hint(ip, 128), user_agent: hint(user_agent, 512))
          next failure unless grant
          # Session creation and consume commit together. An unexpected lost CAS
          # rolls back issuance; it must never return a credential for this request.
          raise AddAuth::Error, "mobile handoff could not finalize" unless @store.consume(row: row, at: now)
          Result.success(user: user, strategy: :external_identity, session: grant.session, grant: grant)
        end
      end

      private

      def current_profile?(row) = @profile&.client?(row.client_id) && @profile.callback(row.client_id) == row.callback
      def text?(value, pattern) = value.is_a?(String) && value.ascii_only? && pattern.match?(value)
      def failure(reason = :invalid_credentials) = Result.failure(reason: reason)

      def hint(value, limit)
        value if value.is_a?(String) && value.valid_encoding? && value.bytesize <= limit && !value.match?(/[\x00-\x1f\x7f]/)
      end
    end
  end
end
