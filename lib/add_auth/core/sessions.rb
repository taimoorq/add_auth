# frozen_string_literal: true

require "securerandom"
require "add_auth/core/mobile_profile"

module AddAuth
  module Core
    class Sessions
      Grant = Struct.new(:session, :bearer) do
        def inspect = "#<AddAuth::Core::Sessions::Grant [FILTERED]>"
      end
      class Entry
        attr_reader :id, :current, :authenticated_with, :authenticated_at, :created_at,
          :last_seen_at, :expires_at, :ip_address, :user_agent, :transport, :client_id

        def initialize(id:, current:, authenticated_with:, authenticated_at:, created_at:,
          last_seen_at:, expires_at:, ip_address:, user_agent:, transport: "browser", client_id: nil)
          @id, @current, @authenticated_with, @authenticated_at, @created_at = id, current,
            authenticated_with, authenticated_at, created_at
          @last_seen_at, @expires_at, @ip_address, @user_agent = last_seen_at, expires_at,
            ip_address, user_agent
          @transport, @client_id = transport, client_id
        end

        def inspect = "#<AddAuth::Core::Sessions::Entry id=#{id} current=#{current.inspect}>"
      end
      PATTERN = /\Alk1:[A-Za-z0-9_-]{43}\z/
      PAGE_SIZE = 50
      Page = Struct.new(:entries, :next_cursor)

      def initialize(store:, digest:, eligible:, lifetime: 43_200, idle_timeout: 1800,
        legacy_bridge_until: nil, clock: Time, access_policy: nil, password_lifecycle: nil, remembered_profile: nil, mobile_profile: nil, on_sign_in: nil, verified_denial: nil)
        unless [lifetime, idle_timeout].all? { |n| n.is_a?(Numeric) && n.finite? && n.positive? } && idle_timeout <= lifetime
          raise ArgumentError, "session timeouts must be positive and idle_timeout <= lifetime"
        end
        unless legacy_bridge_until.nil? || legacy_bridge_until.is_a?(Time)
          raise ArgumentError, "legacy_bridge_until must be an absolute Time or nil"
        end
        @store, @digest, @eligible, @clock = store, digest, eligible, clock
        @access_policy = access_policy
        @password_lifecycle = password_lifecycle
        @on_sign_in = on_sign_in
        @verified_denial = verified_denial
        raise ArgumentError, "invalid mobile profile" unless mobile_profile.nil? || mobile_profile.is_a?(MobileProfile)
        @mobile = mobile_profile
        @lifetime, @idle, @deadline = lifetime, idle_timeout, legacy_bridge_until
        if remembered_profile
          values = remembered_profile.values_at(:lifetime, :idle_timeout)
          unless values.all? { |n| n.is_a?(Numeric) && n.finite? && n.between?(60, 90 * 86_400) } && values.last <= values.first
            raise ArgumentError, "remembered session timeouts must be bounded and idle_timeout <= lifetime"
          end
          @remembered = remembered_profile.slice(:lifetime, :idle_timeout).freeze
        end
      end

      def start(user:, method:, replacing: nil, **hints)
        # The original Rails controller verifies before calling its session hook.
        # A reset between that proof and this lock must invalidate the proof too.
        return if method.to_s == "password" && !user.respond_to?(:password_digest)
        verified_password_digest = user.password_digest if method.to_s == "password"
        @store.with_user(id: user.id, replacing: replacing) do |account|
          next if method.to_s == "password" && account && account.password_digest != verified_password_digest
          create_in_transaction(user: account, method: method, replacing: replacing, **hints)
        end
      end

      def authenticate(**arguments, &verify)
        result = authenticate_result(**arguments, &verify)
        result.grant if result.success?
      end

      def authenticate_result(identifier:, password:, replacing: nil, disclose_policy: false, **hints)
        @store.with_identifier(identifier: identifier, replacing: replacing) do |user|
          @password_lifecycle&.prepare(user: user)
          verified = yield
          valid = user && verified && verified.id == user.id && verified.password_digest == user.password_digest
          denial = @verified_denial&.call(user) if valid && disclose_policy
          valid = @password_lifecycle.verified(user: user, password: password, valid: !!valid) if @password_lifecycle
          grant = create_in_transaction(user: user, method: :password, replacing: replacing, **hints) if valid
          if grant
            Result.success(user: user, strategy: :password, session: grant.session, grant: grant)
          else
            Result.failure(reason: %i[unconfirmed locked disabled].include?(denial) ? denial : :invalid_credentials)
          end
        end
      end

      # Runs inside the store's account transaction. When replacing a browser,
      # that session's account must also be locked on the same connection.
      def create_in_transaction(user:, method:, persist: nil, replacing: nil, proof: nil, remember: false, transport: :browser, client_id: nil, **hints)
        return unless user && @eligible.call(user) == true
        supported_transport = transport == :browser || (transport == :mobile && @mobile&.client?(client_id))
        return unless supported_transport
        return if transport == :mobile && replacing
        raise ArgumentError, "unsupported proof" unless %w[password email_link passkey external_identity].include?(method.to_s)
        return if @access_policy && !@access_policy.sign_in_allowed?(user, method)
        if method.to_s == "passkey"
          return unless proof.is_a?(StepUp::Evidence) && proof.strong? && proof.user_id == user.id &&
            proof.verified_at <= @clock.now && proof.verified_at > @clock.now - 300
        end
        if method.to_s == "external_identity"
          return unless @access_policy && proof.is_a?(ExternalIdentities::SessionProof) && proof.user_id == user.id &&
            proof.verified_at <= @clock.now && proof.verified_at > @clock.now - 300 &&
            @access_policy.external_credential_current?(user: user, id: proof.credential_id, version: proof.credential_version)
          hints = hints.merge(authentication_external_id: proof.credential_id,
            authentication_external_version: proof.credential_version)
        end
        if user.respond_to?(:add_auth_policy_version)
          hints = hints.merge(authentication_policy_version: @access_policy ? @access_policy.version(user) : user.add_auth_policy_version,
            authentication_credential_id: proof&.credential_id, authentication_uv: proof&.user_verification || false)
        end
        raw = (transport == :mobile) ? @mobile.bearer : bearer
        now = @clock.now
        if replacing
          prior = @store.find_for_user_in_transaction(user_id: replacing.user_id, session_id: replacing.id)
          @store.update(prior, revoked_at: now) if prior && !prior.revoked_at && prior.token_digest == replacing.token_digest
        end
        writer = persist || ->(**attributes) { @store.create(user: user, **attributes) }
        duration = @lifetime
        if @remembered
          remembered = remember == true
          duration = @remembered.fetch(:lifetime) if remembered
          hints = hints.merge(remembered: remembered, idle_timeout: remembered ? @remembered.fetch(:idle_timeout) : @idle)
        end
        if transport == :mobile
          duration = @mobile.lifetime
          hints = hints.merge(transport: "mobile", client_id: client_id, mobile_idle_timeout: @mobile.idle_timeout)
          hints[:remembered] = false if @remembered
        end
        row = writer.call(token_digest: @digest.digest(raw), authenticated_with: method.to_s,
          authenticated_at: now, expires_at: now + duration, last_seen_at: now, **hints)
        @on_sign_in&.call(user: user, session: row, at: now)
        Grant.new(session: row, bearer: raw)
      end

      # The adapter must pass only the value returned by Rails cookies.signed.
      def resume(signed_value:)
        lookup = cookie_lookup(signed_value)
        return unless lookup
        legacy = lookup.key?(:id)
        @store.with_session(**lookup) do |user, row|
          now = @clock.now
          next unless transport_for(row) == "browser" && live?(user, row, now: now)
          if legacy
            next if row.token_digest || now >= @deadline
            raw = bearer
            @store.update(row, token_digest: @digest.digest(raw), expires_at: [now + @lifetime, @deadline, row.expires_at].compact.min,
              last_seen_at: now, authenticated_with: nil, authenticated_at: nil)
            Grant.new(session: row, bearer: raw)
          else
            @store.update(row, last_seen_at: now) if row.last_seen_at <= now - 60
            Grant.new(session: row)
          end
        end
      end

      # Only the exact Authorization bearer value enters this parser. Cookies,
      # query parameters and legacy host API tokens are not alternate inputs.
      def resume_mobile(bearer:)
        return unless @mobile && bearer.is_a?(String) && MobileProfile::PATTERN.match?(bearer)
        @store.with_session(digest: @digest.digest(bearer)) do |user, row|
          now = @clock.now
          next unless transport_for(row) == "mobile" && live?(user, row, now: now)
          @store.update(row, last_seen_at: now) if row.last_seen_at <= now - 60
          Grant.new(session: row)
        end
      end

      # A trusted cookie identifies what to retire, even if that account is now
      # ineligible. This snapshot is replacement input, never authentication.
      def replacement_for(signed_value:)
        lookup = cookie_lookup(signed_value)
        return unless lookup
        @store.with_session(**lookup) do |_user, row|
          row if transport_for(row) == "browser" && !(lookup.key?(:id) && row&.token_digest)
        end
      end

      def revoke(session:)
        @store.with_session(id: session.id) do |_user, row|
          @store.update(row, revoked_at: @clock.now) if row && !row.revoked_at && row.token_digest == session.token_digest
        end
      end

      # Returns display-safe metadata only. Bearers and digests never cross this
      # boundary, even when a host chooses to render its own management page.
      def list(user:, current_session_id: nil)
        list_page(user: user, current_session_id: current_session_id).entries
      end

      def list_page(user:, current_session_id: nil, before: nil)
        empty = Page.new(entries: [])
        return empty unless user && @eligible.call(user) == true
        return empty unless before.nil? || before.to_s.match?(/\A[1-9]\d{0,18}\z/)

        now = @clock.now
        candidates = @store.list_for_user(user_id: user.id, before: before&.to_i,
          excluding: current_session_id, limit: PAGE_SIZE + 1, now: now,
          active_after: now - [@idle, @remembered&.fetch(:idle_timeout) || @idle, @mobile&.idle_timeout || @idle].max, legacy: !!(@deadline && now < @deadline))
        cursor = candidates[PAGE_SIZE - 1].id if candidates.length > PAGE_SIZE
        rows = candidates.first(PAGE_SIZE)
        if before.nil? && current_session_id
          current = @store.find_for_user(user_id: user.id, session_id: current_session_id)
          rows.unshift(current) if current
        end
        entries = rows.filter_map do |row|
          next unless live?(user, row, now: now)

          Entry.new(id: row.id, current: row.id == current_session_id,
            authenticated_with: row.authenticated_with, authenticated_at: row.authenticated_at,
            created_at: row.created_at, last_seen_at: row.last_seen_at, expires_at: row.expires_at,
            ip_address: row.ip_address, user_agent: row.user_agent,
            transport: transport_for(row), client_id: row.respond_to?(:client_id) ? row.client_id : nil)
        end
        Page.new(entries: entries, next_cursor: cursor)
      end

      # Both the initiating bearer and target ownership are checked under lock.
      def revoke_one(user:, session:, session_id:)
        return false unless session_id.is_a?(Integer) || session_id.to_s.match?(/\A[1-9]\d*\z/)

        with_live_session(user: user, session: session) do |account, _current, now|
          target = @store.find_for_user_in_transaction(user_id: account.id, session_id: session_id.to_i)
          next false unless target
          @store.update(target, revoked_at: now) unless target.revoked_at
          true
        end || false
      end

      # Password proof is obtained from the locked, current account. Intake
      # limits must be applied by the caller before reaching this expensive port.
      def reauthenticate(user:, session:, purpose:, policy:)
        with_live_session(user: user, session: session) do |account, row, _now|
          next Result.failure(reason: :elevation_required) if @access_policy && !@access_policy.sign_in_allowed?(account, :password)
          @password_lifecycle&.prepare(user: account)
          verified = yield account
          valid = verified && verified.id == account.id && verified.password_digest == account.password_digest
          valid = @password_lifecycle.verified(user: account, password: nil, valid: !!valid, rehash: false) if @password_lifecycle
          next Result.failure(reason: :invalid_credentials) unless valid
          evidence = StepUp::Evidence.new(user_id: account.id, session_id: row.id,
            method: :password, verified_at: @clock.now, session_digest: row.token_digest,
            credential_version: policy.password_version(account))
          policy.authorize(user: account, session_id: row.id, purpose: purpose, evidence: evidence)
        end || Result.failure(reason: :elevation_required)
      end

      def revoke_all(user:, session:, grant:)
        with_authority(user: user, session: session, grant: grant, purpose: :sign_out_everywhere) do |account, _row, now|
          @store.revoke_all_in_transaction(user_id: account.id, at: now)
        end || false
      end

      def rotate_for_step_up(user:, session:, grant:)
        return unless grant.is_a?(StepUp::Grant)
        with_authority(user: user, session: session, grant: grant, purpose: grant.purpose) do |account, row, _now|
          rotate_in_transaction(user: account, session: row, grant: grant)
        end
      end

      # Caller owns the account transaction, as with email-token consumption.
      def current_in_transaction(user:, session:)
        return unless user && session && session.user_id == user.id
        row = @store.find_for_user_in_transaction(user_id: user.id, session_id: session.id)
        row if live?(user, row, now: @clock.now) && row.token_digest == session.token_digest
      end

      def rotate_in_transaction(user:, session:, grant:)
        row = current_in_transaction(user: user, session: session)
        return unless row && grant.is_a?(StepUp::Grant) && grant.valid_for?(user: user,
          user_id: user.id, session_id: row.id, session_digest: row.token_digest, purpose: grant.purpose, now: @clock.now)
        raw = (transport_for(row) == "mobile") ? @mobile.bearer : bearer
        attributes = {token_digest: @digest.digest(raw), elevated_at: grant.verified_at,
                      elevated_with: grant.method.to_s, elevation_purpose: grant.purpose.to_s,
                      elevation_credential_id: grant.credential_id, elevation_uv: grant.user_verification,
                      last_seen_at: @clock.now}
        if row.respond_to?(:elevation_version)
          attributes[:elevation_version] = grant.credential_version
          attributes[:elevation_expires_at] = grant.expires_at
        end
        @store.update(row, **attributes)
        Grant.new(session: row, bearer: raw)
      end

      # A guard can call this without a block. Mutations must use the block so
      # eligibility, bearer generation and proof are checked under the same lock.
      # Hosts own resource authorization and target/version checks inside it.
      def with_elevation(user:, session:, purpose:, policy:)
        with_live_session(user: user, session: session) do |account, row, _now|
          result = elevation_in_transaction(user: account, session: row, purpose: purpose, policy: policy)
          next result unless result.success?
          yield account if block_given?
          result
        end || Result.failure(reason: :elevation_required)
      end

      def elevation_in_transaction(user:, session:, purpose:, policy:)
        row = current_in_transaction(user: user, session: session)
        now = @clock.now
        return Result.failure(reason: :elevation_required) unless row&.respond_to?(:elevation_version) && row.elevated_at &&
          row.elevation_purpose == purpose.to_s && row.elevation_expires_at && now < row.elevation_expires_at
        evidence_class = (row.elevated_with == "external_identity") ? StepUp::ExternalEvidence : StepUp::Evidence
        extra = (row.elevated_with == "external_identity") ? {purpose: purpose} : {}
        evidence = evidence_class.send(:new, **extra, user_id: user.id, session_id: row.id,
          method: row.elevated_with, verified_at: row.elevated_at, session_digest: row.token_digest,
          credential_id: row.elevation_credential_id, user_verification: row.elevation_uv,
          credential_version: row.elevation_version)
        policy.authorize(user: user, session_id: row.id, purpose: purpose, evidence: evidence)
      end

      def self.safe_return(value)
        value if value.is_a?(String) && value.start_with?("/") && !value.start_with?("//") &&
          !value.match?(/[\\\x00-\x20\x7f]/) && !value.match?(/%[0-9a-f]{2}/i)
      end

      private

      def cookie_lookup(value)
        if value.is_a?(String) && PATTERN.match?(value)
          {digest: @digest.digest(value)}
        elsif value.is_a?(Integer) && value.positive? && @deadline && @clock.now < @deadline
          {id: value}
        end
      end

      def with_authority(user:, session:, grant:, purpose:)
        return unless grant.is_a?(StepUp::Grant)
        with_live_session(user: user, session: session) do |account, row, now|
          next unless grant.valid_for?(user: account, user_id: account.id, session_id: row.id,
            session_digest: row.token_digest, purpose: purpose, now: now)
          yield account, row, now
        end
      end

      def with_live_session(user:, session:)
        return unless user && session
        @store.with_session(id: session.id) do |account, row|
          now = @clock.now
          next unless account && account.id == user.id && live?(account, row, now: now) &&
            row.token_digest == session.token_digest
          yield account, row, now
        end
      end

      def live?(user, row, now:)
        return false unless user && row && @eligible.call(user) == true && !row.revoked_at
        return false if @access_policy && !@access_policy.session_allowed?(user, row)
        legacy = !row.token_digest && @deadline && now < @deadline
        idle = @idle
        if transport_for(row) == "mobile"
          return false unless @mobile&.client?(row.client_id) && row.token_digest
          stored_idle = row.mobile_idle_timeout
          return false unless stored_idle.is_a?(Integer) && stored_idle.between?(60, 90 * 86_400)
          idle = [stored_idle, @mobile.idle_timeout].min
          return false unless row.authenticated_at && (row.authenticated_at + @mobile.lifetime > now)
        elsif transport_for(row) != "browser"
          return false
        elsif @remembered && row.respond_to?(:remembered) && row.remembered == true
          stored_idle = row.idle_timeout
          return false unless stored_idle.is_a?(Numeric) && stored_idle.finite? && stored_idle.positive?
          idle = [stored_idle, @remembered.fetch(:idle_timeout)].min
          return false unless row.authenticated_at && row.authenticated_at + @remembered.fetch(:lifetime) > now
        end
        (legacy || (row.expires_at && row.last_seen_at)) &&
          (!row.expires_at || row.expires_at > now) && (!row.last_seen_at || row.last_seen_at > now - idle)
      end

      def transport_for(row) = row.respond_to?(:transport) ? row.transport : "browser"

      def bearer = "lk1:#{SecureRandom.urlsafe_base64(32)}"
    end
  end
end
