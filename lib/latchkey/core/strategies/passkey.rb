# frozen_string_literal: true

require "webauthn"
require "json"
require "base64"
require "uri"
require "public_suffix"

module Latchkey
  module Core
    module Strategies
      class Passkey
        PURPOSE = :manage_passkeys
        PAYLOAD_LIMIT = 65_536
        Entry = Data.define(:id, :nickname, :created_at, :last_used_at, :backup_eligible, :backup_state)

        def initialize(store:, sessions:, policy:, access_policy:, digest:, eligible:, rp_id:, origins:, name:,
          notify:, limiter:, anonymous_limit: 1000, clock: Time, allow_localhost: false, support_url: nil, on_failure: ->(_reason) {})
          @store, @sessions, @policy, @access, @digest, @eligible = store, sessions, policy, access_policy, digest, eligible
          @clock, @notify, @support_url, @on_failure = clock, notify, support_url, on_failure
          @limiter, @anonymous_limit = limiter, anonymous_limit
          unless anonymous_limit.is_a?(Integer) && anonymous_limit.positive?
            raise Latchkey::Error, "passkeys.anonymous_limit must be a positive integer"
          end
          raise Latchkey::Error, "support_url must be a safe local support page" if support_url && !Sessions.safe_return(support_url)
          @binding = BrowserBinding.new(digest: digest)
          validate_origins!(rp_id, origins, allow_localhost)
          @rp = WebAuthn::RelyingParty.new(id: rp_id, name: name, allowed_origins: origins.dup,
            encoding: :base64url, acceptable_attestation_types: ["None"], credential_options_timeout: 120_000)
          @configuration_digest = digest.digest(JSON.generate([rp_id, origins.sort]))
        end

        def registration_options(user:, session:, browser_secret:)
          @store.with_user(id: user&.id) do |account|
            proof = management_proof(account, session, allow_recovery: true)
            next failure(:elevation_required) unless proof.success? && @binding.valid?(browser_secret)
            @store.update(account, webauthn_id: @binding.generate) unless account.webauthn_id
            options = @rp.options_for_registration(user: {id: account.webauthn_id, name: account.email_address},
              exclude: @store.credentials(user: account).map(&:external_id), attestation: "none",
              authenticator_selection: {residentKey: "required", requireResidentKey: true, userVerification: "required"},
              extensions: {credProps: true})
            create_options(options, kind: "registration", user: account, session: session,
              purpose: proof.credential.purpose, browser_secret: browser_secret)
          end
        end

        def authentication_options(browser_secret:, user: nil, session: nil, purpose: nil)
          return failure unless @binding.valid?(browser_secret)
          if user || session || purpose
            @store.with_user(id: user&.id) do |account|
              next failure(:elevation_required) unless account && @sessions.current_in_transaction(user: account, session: session) &&
                @policy.reauthentication_rule_for(purpose) && @policy.methods_for(user: account, purpose: purpose).include?(:passkey)
              options = @rp.options_for_authentication(allow: @store.credentials(user: account).map(&:external_id), user_verification: "required")
              create_options(options, kind: "assertion", user: account, session: session, purpose: purpose, browser_secret: browser_secret)
            end
          else
            return failure(:rate_limited) unless @limiter.call(key: @digest.digest("passkey:anonymous-ceremonies"), limit: @anonymous_limit)
            options = @rp.options_for_authentication(user_verification: "required")
            create_options(options, kind: "assertion", browser_secret: browser_secret)
          end
        end

        def register(transaction:, credential_response:, user:, session:, browser_secret:, nickname: nil)
          payload = parse_payload(credential_response)
          return failure unless payload && @binding.valid?(transaction)
          @store.with_ceremony(digest: @digest.digest(transaction), user_id: user&.id) do |account, ceremony|
            next failure unless valid_ceremony?(account, ceremony, "registration", browser_secret) &&
              bound_session?(ceremony, session) && ceremony.user_id == account.id
            proof = management_proof(account, session, purpose: ceremony.authentication_purpose)
            next failure(:elevation_required) unless proof.success?
            verified = verify { @rp.verify_registration(payload, ceremony.challenge, user_verification: true, user_presence: true) }
            next verified if verified.is_a?(Result)
            next failure unless valid_backup?(verified) && verified.raw_id == verified.response.authenticator_data.credential.id
            label = normalized_label(nickname || "Passkey")
            next failure unless label
            credential = @store.create_credential(user: account, external_id: verified.id,
              public_key: verified.public_key, sign_count: verified.sign_count,
              backup_eligible: verified.backup_eligible?, backup_state: verified.backed_up?, nickname: label,
              aaguid: verified.response.authenticator_data.aaguid, transports: transports(payload))
            next failure unless credential
            @store.update(ceremony, consumed_at: @clock.now)
            grant = nil
            if proof.credential.purpose == :recover_passkeys
              @store.revoke_other_sessions(user: account, except: session, at: @clock.now)
              @store.invalidate_proofs(user: account, at: @clock.now)
              grant = @sessions.rotate_in_transaction(user: account, session: session, grant: proof.credential)
              raise Latchkey::Error, "recovery replacement could not finalize" unless grant
              @store.update(grant.session, elevated_at: nil, elevation_version: nil, elevation_expires_at: nil)
              @notify.call(user: account, kind: :recovery_completed, at: @clock.now)
            else
              @notify.call(user: account, kind: :passkey_added, at: @clock.now)
            end
            Result.success(user: account, strategy: :passkey, credential: credential, session: grant&.session, grant: grant)
          end
        end

        def authenticate(transaction:, credential_response:, browser_secret:, session: nil, replacing: nil, **hints)
          payload = parse_payload(credential_response)
          return failure unless payload && @binding.valid?(transaction)
          locator = @store.credential(id: payload["id"])
          return failure unless locator
          @store.with_ceremony(digest: @digest.digest(transaction), user_id: locator.user_id, replacing: replacing) do |account, ceremony|
            next failure unless valid_ceremony?(account, ceremony, "assertion", browser_secret)
            next failure unless ceremony.user_id.nil? == session.nil?
            credential = @store.credential(id: payload["id"])
            next failure unless credential && credential.user_id == account.id && !credential.revoked_at
            if ceremony.user_id
              next failure(:elevation_required) unless ceremony.user_id == account.id && bound_session?(ceremony, session) &&
                @sessions.current_in_transaction(user: account, session: session)
            else
              next failure unless @access.sign_in_allowed?(account, :passkey)
            end
            verified = verify do
              @rp.verify_authentication(payload, ceremony.challenge, public_key: credential.public_key,
                sign_count: credential.sign_count, user_verification: true, user_presence: true)
            end
            next verified if verified.is_a?(Result)
            next failure unless verified.user_handle == account.webauthn_id && valid_backup?(verified) &&
              verified.backup_eligible? == credential.backup_eligible
            evidence = StepUp::Evidence.new(user_id: account.id, session_id: session&.id, method: :passkey,
              verified_at: @clock.now, session_digest: session&.token_digest, credential_id: credential.external_id,
              credential_version: credential.public_key, user_verification: true)
            grant = if ceremony.user_id
              authorization = @policy.authorize(user: account, session_id: session.id,
                purpose: ceremony.authentication_purpose, evidence: evidence)
              next authorization unless authorization.success?
              @sessions.rotate_in_transaction(user: account, session: session, grant: authorization.credential)
            else
              @sessions.create_in_transaction(user: account, method: :passkey, proof: evidence, replacing: replacing, **hints)
            end
            next failure(:elevation_required) unless grant
            @store.update(credential, sign_count: verified.sign_count, backup_state: verified.backed_up?, last_used_at: @clock.now)
            @store.update(ceremony, consumed_at: @clock.now)
            Result.success(user: account, strategy: :passkey, credential: grant, session: grant.session)
          end
        end

        def list(user:, session:)
          @store.with_user(id: user&.id) do |account|
            next [] unless account && @sessions.current_in_transaction(user: account, session: session)
            @store.credentials(user: account).map do |row|
              Entry.new(id: row.id, nickname: row.nickname, created_at: row.created_at, last_used_at: row.last_used_at,
                backup_eligible: row.backup_eligible, backup_state: row.backup_state)
            end
          end
        end

        def rename(user:, session:, id:, nickname:)
          label = normalized_label(nickname)
          return failure unless label
          @store.with_user(id: user&.id) do |account|
            next failure unless account && @sessions.current_in_transaction(user: account, session: session)
            row = @store.credentials(user: account).find { |item| item.id.to_s == id.to_s }
            next failure unless row
            @store.update(row, nickname: label)
            Result.success(user: account, strategy: :passkey)
          end
        end

        def remove(user:, session:, id:)
          @store.with_user(id: user&.id) do |account|
            next failure(:elevation_required) unless management_proof(account, session).success?
            rows = @store.credentials(user: account)
            row = rows.find { |item| item.id.to_s == id.to_s }
            next failure unless row
            next failure unless rows.length > 1 || @access.fallback?(account)
            @store.update(row, revoked_at: @clock.now)
            @notify.call(user: account, kind: :passkey_removed, at: @clock.now)
            Result.success(user: account, strategy: :passkey)
          end
        end

        def change_policy(user:, session:, strict:, acknowledged:)
          return failure unless [true, false].include?(strict)
          return failure if strict && (acknowledged != true || @support_url.to_s.empty?)
          @store.with_user(id: user&.id) do |account|
            proof = @sessions.elevation_in_transaction(user: account, session: session, purpose: :manage_policy, policy: @policy)
            next failure(:elevation_required) unless proof.success? && proof.credential.method == :passkey && proof.credential.user_verification
            next failure unless @store.credentials(user: account).any?
            row = @sessions.current_in_transaction(user: account, session: session)
            @store.update(account, latchkey_strict: strict, latchkey_policy_version: @access.version(account) + 1)
            @store.revoke_other_sessions(user: account, except: row, at: @clock.now)
            @store.invalidate_proofs(user: account, at: @clock.now)
            @store.update(row, authentication_policy_version: @access.version(account), authenticated_with: "passkey",
              authenticated_at: proof.credential.verified_at, authentication_credential_id: proof.credential.credential_id,
              authentication_uv: true)
            grant = @sessions.rotate_in_transaction(user: account, session: row, grant: proof.credential)
            raise Latchkey::Error, "policy transition could not finalize" unless grant
            @notify.call(user: account, kind: :policy_changed, at: @clock.now)
            Result.success(user: account, strategy: :passkey, session: grant.session, credential: grant)
          end
        end

        def cancel(transaction:, browser_secret:)
          return false unless @binding.valid?(transaction)
          @store.cancel(digest: @digest.digest(transaction)) do |record|
            next false unless record && @binding.matches?(record.browser_digest, browser_secret)
            @store.update(record, consumed_at: @clock.now) unless record.consumed_at
            true
          end
        end

        private

        def management_proof(account, session, purpose: PURPOSE, allow_recovery: false)
          return failure(:elevation_required) unless account
          return failure(:elevation_required) if purpose.to_sym == :recover_passkeys && !@access.recoverable?(account)
          proof = @sessions.elevation_in_transaction(user: account, session: session, purpose: purpose, policy: @policy)
          return proof if proof.success? || !allow_recovery || purpose.to_sym != PURPOSE || !@access.recoverable?(account)
          @sessions.elevation_in_transaction(user: account, session: session, purpose: :recover_passkeys, policy: @policy)
        end

        def create_options(options, kind:, browser_secret:, user: nil, session: nil, purpose: nil)
          identifier = @binding.generate
          @store.create_ceremony(digest: @digest.digest(identifier), challenge: options.challenge, kind: kind,
            browser_digest: @binding.digest(browser_secret), configuration_digest: @configuration_digest,
            user_id: user&.id, session_id: session&.id, session_digest: session&.token_digest,
            authentication_purpose: purpose&.to_s, expires_at: @clock.now + 300)
          Result.success(user: user, strategy: :passkey, credential: {transaction: identifier, publicKey: options.as_json})
        end

        def valid_ceremony?(account, row, kind, browser_secret)
          account && @eligible.call(account) == true && row && row.kind == kind && !row.consumed_at &&
            row.expires_at > @clock.now && row.configuration_digest == @configuration_digest &&
            @binding.matches?(row.browser_digest, browser_secret)
        end

        def bound_session?(ceremony, session)
          session && ceremony.session_id == session.id && ceremony.session_digest == session.token_digest
        end

        def valid_backup?(credential) = !credential.backed_up? || credential.backup_eligible?

        def normalized_label(label)
          label.strip if label.is_a?(String) && label.valid_encoding? && label.bytesize <= 240 &&
            label.strip.length.between?(1, 60) && !label.match?(/[\x00-\x1f\x7f]/)
        end

        def transports(payload)
          value = payload.dig("response", "transports")
          value.is_a?(Array) ? value & %w[usb nfc ble internal hybrid] : []
        end

        def parse_payload(value)
          return unless value.is_a?(Hash) && JSON.generate(value).bytesize <= PAYLOAD_LIMIT
          id = value["id"]
          return unless id.is_a?(String) && id.bytesize.between?(1, 2048) && /\A[A-Za-z0-9_-]+\z/.match?(id) && value["rawId"] == id
          client = JSON.parse(Base64.urlsafe_decode64(value.fetch("response").fetch("clientDataJSON")))
          return unless client.is_a?(Hash) && [nil, false].include?(client["crossOrigin"]) && !client.key?("topOrigin")
          value
        rescue ArgumentError, TypeError, KeyError, NoMethodError, JSON::ParserError
          nil
        end

        def verify
          yield
        rescue WebAuthn::SignCountVerificationError
          failure(:counter_regression)
        rescue
          # Library parsing/verification handles attacker-controlled binary data.
          # This rescue surrounds verification only, never persistence or finalization.
          failure
        end

        def validate_origins!(rp_id, origins, allow_localhost)
          valid_id = rp_id.is_a?(String) && /\A[a-z0-9]+(?:[.-][a-z0-9]+)*\z/.match?(rp_id) &&
            (PublicSuffix.domain(rp_id) || (allow_localhost && rp_id == "localhost"))
          valid = valid_id && origins.is_a?(Array) && origins.any? && origins.all? do |origin|
            uri = URI.parse(origin)
            secure = uri.scheme == "https" || (allow_localhost && uri.scheme == "http" && %w[localhost 127.0.0.1].include?(uri.host))
            secure && uri.host && (uri.host == rp_id || uri.host.end_with?(".#{rp_id}")) &&
              !uri.userinfo && !uri.query && !uri.fragment && uri.path.empty? && uri.to_s == origin
          end
          raise Latchkey::Error, "configure a stable RP ID and exact HTTPS origins" unless valid
        rescue URI::InvalidURIError, TypeError
          raise Latchkey::Error, "configure a stable RP ID and exact HTTPS origins"
        end

        def failure(reason = :invalid_credentials)
          @on_failure.call(reason)
          Result.failure(reason: reason)
        end
      end
    end
  end
end
