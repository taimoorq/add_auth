# frozen_string_literal: true

require "securerandom"

module Latchkey
  module Core
    module Strategies
      # Internal sign-in token lifecycle, NOT an HTTP endpoint. Run issuance
      # behind a uniform asynchronous intake/rate-limit boundary. A nil return
      # does not make account-dependent database work timing indistinguishable.
      # Sign-in and reauthentication have distinct purposes. Store transactions
      # enclose Core policy, proof consumption and the session finalizer.
      class EmailLink
        include Delivery

        DEFAULT_TOKEN_LIFETIME = 20 * 60
        TOKEN_BYTES = 32
        TOKEN_PATTERN = /\A[A-Za-z0-9_-]{43}\z/

        def initialize(store:, digest:, delivery_cipher:, eligible:, normalize_identifier:, identifier_for:,
          clock: Time, random: SecureRandom, token_lifetime: DEFAULT_TOKEN_LIFETIME, same_browser: false, purpose: :sign_in, sessions: nil, policy: nil, proof_allowed: ->(_user) { true })
          unless token_lifetime.is_a?(Numeric) && token_lifetime.finite? && token_lifetime.positive?
            raise ArgumentError, "token_lifetime must be finite and positive"
          end
          @store, @digest, @cipher = store, digest, delivery_cipher
          @eligible, @normalize, @identifier_for = eligible, normalize_identifier, identifier_for
          @clock, @random, @token_lifetime = clock, random, token_lifetime
          raise ArgumentError, "same_browser must be true or false" unless [true, false].include?(same_browser)
          @purpose = purpose.to_s
          raise ArgumentError, "unsupported email purpose" unless %w[sign_in reauthentication recovery].include?(@purpose)
          if @purpose != "sign_in" && (!sessions || !policy)
            raise ArgumentError, "reauthentication requires sessions and purpose policy"
          end
          @sessions, @policy, @proof_allowed = sessions, policy, proof_allowed
          @same_browser = same_browser || @purpose == "reauthentication"
          @binding = BrowserBinding.new(digest: digest)
        end

        def browser_digest(secret) = @same_browser ? @binding.digest(secret) : nil

        def confirmation_page(preview)
          return "invalid_link" unless preview
          preview.fetch(:browser_matches) ? "confirmation" : "different_browser"
        end

        def issue(identifier:, requested_ip_address: nil, request_id: nil, browser_digest: nil, session_id: nil, session_digest: nil, authentication_purpose: nil)
          return if @same_browser && (!browser_digest.is_a?(String) || browser_digest.empty?)
          return nil unless identifier.is_a?(String) && identifier.valid_encoding? && identifier.bytesize.between?(1, 254)

          normalized = @normalize.call(identifier)
          return nil unless normalized.is_a?(String) && normalized.valid_encoding? && normalized.bytesize.between?(1, 254)
          raw = @random.urlsafe_base64(TOKEN_BYTES)
          raise Latchkey::Error, "random source returned an invalid token" unless valid_token?(raw)
          digest = @digest.digest(raw)
          at = @clock.now
          expires_at = at + @token_lifetime
          payload = @cipher.encrypt(token: raw, digest: digest, expires_at: expires_at)
          @store.with_user(identifier: normalized) do |user|
            next if request_id && @store.issued?(request_id: request_id)
            if user && @eligible.call(user) == true && @proof_allowed.call(user) == true && @normalize.call(@identifier_for.call(user)) == normalized
              context = {}
              if @purpose == "reauthentication"
                row = @store.session_for(user: user, id: session_id)
                next unless row && row.token_digest == session_digest && @sessions.current_in_transaction(user: user, session: row) &&
                  @policy.reauthentication_rule_for(authentication_purpose) && @policy.methods_for(user: user, purpose: authentication_purpose).include?(:email_link)
                context = {session_id: row.id, session_digest: row.token_digest, authentication_purpose: authentication_purpose.to_s}
              end
              @store.replace_pending(user: user, purpose: @purpose, **context, digest: digest, expires_at: expires_at,
                created_at: at, delivery_payload: payload, identifier_digest: @digest.digest("identifier:#{normalized}"),
                requested_ip_address: requested_ip_address, **(browser_digest ? {browser_digest: browser_digest} : {}), **(request_id ? {request_id: request_id} : {}))
            end
          end
          nil
        end

        # The finalizer must persist the session in the same transaction; cookie
        # writing/delivery happens only after this method successfully returns.
        # Pass a trusted current_session snapshot here and as replacing: to the
        # session finalizer so both accounts are locked during a browser switch.
        def consume(token:, current_user_id: nil, current_session: nil, switch_account: false, browser_secret: nil)
          raise ArgumentError, "use reauthenticate for this proof" if @purpose == "reauthentication"
          raise ArgumentError, "a transactional session finalizer is required" unless block_given? || @purpose == "recovery"
          return failure(:invalid_credentials) unless valid_token?(token)

          current_user_id = current_session.user_id if current_session
          @store.with_token(digest: @digest.digest(token), current_session: current_session) do |user, record|
            reason = rejection(user, record)
            reason ||= :invalid_credentials unless browser_matches?(record, browser_secret)
            reason ||= :invalid_credentials if current_user_id && user && current_user_id != user.id && switch_account != true
            if reason
              failure(reason)
            else
              @store.consume(record: record, at: @clock.now)
              grant = nil
              session = @store.finalize_session(user: user) do |persist|
                if @purpose == "recovery"
                  grant = recovery_session(user, record, persist, current_session)
                  grant.session
                else
                  yield user, persist
                end
              end
              Latchkey::Result.success(user: user, strategy: :email_link, session: session, grant: grant)
            end
          end
        end

        def reauthenticate(token:, session:, browser_secret:)
          return failure(:invalid_credentials) unless @purpose == "reauthentication" && valid_token?(token)
          @store.with_token(digest: @digest.digest(token)) do |user, record|
            reason = rejection(user, record)
            reason ||= :invalid_credentials unless browser_matches?(record, browser_secret)
            reason ||= :elevation_required unless session && record && session.id == record.session_id &&
              session.token_digest == record.session_digest && user && @sessions.current_in_transaction(user: user, session: session)
            next failure(reason) if reason
            evidence = StepUp::Evidence.new(user_id: user.id, session_id: session.id, method: :email_link,
              verified_at: @clock.now, session_digest: session.token_digest, credential_version: record.identifier_digest)
            result = @policy.authorize(user: user, session_id: session.id, purpose: record.authentication_purpose, evidence: evidence)
            next result unless result.success?
            rotated = @sessions.rotate_in_transaction(user: user, session: session, grant: result.credential)
            next failure(:elevation_required) unless rotated
            @store.consume(record: record, at: @clock.now)
            Result.success(user: user, strategy: :step_up, session: rotated.session, credential: rotated)
          end
        end

        # Delivery workers fetch by digest/issuance identity, never raw job args.
        # Repeated calls return the SAME token. A future worker must recheck before
        # sending and tolerate an email becoming stale while already in transit.
        def delivery_token(digest:)
          @store.with_token(digest: digest) do |user, record|
            unless rejection(user, record) || record.delivery_payload.nil?
              token = @cipher.decrypt(payload: record.delivery_payload, digest: record.digest)
              token if valid_token?(token) && @digest.matches?(record.digest, token)
            end
          end
        end

        def preview(token:, browser_secret: nil)
          return unless valid_token?(token)
          @store.with_token(digest: @digest.digest(token)) do |user, record|
            unless rejection(user, record)
              address = @identifier_for.call(user)
              local, domain = address.split("@", 2)
              {user_id: user.id, masked_address: "#{local[0]}•••@#{domain}", browser_matches: browser_matches?(record, browser_secret)}
            end
          end
        end

        private

        def recovery_session(user, record, persist, previous)
          initial = @sessions.create_in_transaction(user: user, method: :email_link, persist: persist, replacing: previous)
          raise Latchkey::Error, "recovery could not create a session" unless initial
          evidence = StepUp::Evidence.new(user_id: user.id, session_id: initial.session.id, method: :email_link,
            verified_at: @clock.now, session_digest: initial.session.token_digest, credential_version: record.identifier_digest)
          proof = @policy.authorize(user: user, session_id: initial.session.id, purpose: :recover_passkeys, evidence: evidence)
          raise Latchkey::Error, "recovery is not permitted" unless proof.success?
          grant = @sessions.rotate_in_transaction(user: user, session: initial.session, grant: proof.credential)
          raise Latchkey::Error, "recovery could not finalize" unless grant
          # Preserve the transaction writer's exact newly created row identity.
          grant.session = @store.refresh_session(initial.session)
          grant
        end

        def delivery_details(user, record)
          raw = @cipher.decrypt(payload: record.delivery_payload, digest: record.digest)
          {token: raw, recipient: @identifier_for.call(user)} if valid_token?(raw) && @digest.matches?(record.digest, raw)
        end

        def browser_matches?(record, secret)
          stored = record.browser_digest if record&.respond_to?(:browser_digest)
          return true if !@same_browser && stored.nil?
          @binding.matches?(stored, secret)
        end

        def valid_token?(token)
          token.is_a?(String) && token.bytesize == 43 && token.ascii_only? && TOKEN_PATTERN.match?(token)
        end

        def rejection(user, record)
          return :invalid_credentials unless user && record && record.purpose == @purpose
          return :disabled unless @eligible.call(user) == true && @proof_allowed.call(user) == true
          identifier = @normalize.call(@identifier_for.call(user))
          return :revoked_token unless @digest.matches?(record.identifier_digest, "identifier:#{identifier}")
          if @purpose == "reauthentication"
            row = @store.session_for(user: user, id: record.session_id)
            return :elevation_required unless row && row.token_digest == record.session_digest &&
              @sessions.current_in_transaction(user: user, session: row) &&
              @policy.reauthentication_rule_for(record.authentication_purpose) && @policy.methods_for(user: user, purpose: record.authentication_purpose).include?(:email_link)
          end
          return :revoked_token if record.revoked_at
          return :consumed_token if record.consumed_at
          :expired_token if record.expires_at <= @clock.now
        end

        def failure(reason) = Latchkey::Result.failure(reason: reason)
      end
    end
  end
end
