# frozen_string_literal: true

require "json"
require "securerandom"

module AddAuth
  module Core
    class AccountLifecycle
      include Delivery

      PURPOSES = %w[confirm reset_password unlock].freeze
      TOKEN = /\Aac1:[A-Za-z0-9_-]{43}\z/
      SECURITY_ATTRIBUTES = %w[id email email_address password password_confirmation password_digest encrypted_password
        confirmed_at unconfirmed_email locked_at disabled_at deleted_at failed_attempts confirmation_token
        reset_password_token unlock_token authentication_token].freeze
      class Conflict < StandardError; end
      class InvalidPassword < StandardError; end
      class DeletionRejected < StandardError; end

      class NewAccount
        attr_reader :user, :user_id
        def initialize(user:)
          @user, @user_id = user, user.id
          freeze
        end
        private_class_method :new
        def inspect = "#<AddAuth::Core::AccountLifecycle::NewAccount [FILTERED]>"
      end

      def self.validate_host_write!(changes:, enabled:)
        if enabled && (changes.keys.map(&:to_s) & %w[email_address unconfirmed_email]).any?
          raise AddAuth::Error, "change account email through the account lifecycle command"
        end
      end

      def initialize(store:, digest:, delivery_cipher:, policy:, password_policy:, trusted_address:, clock: Time, random: SecureRandom,
        lifetime: 3600, notify: ->(**) {}, sessions: nil, step_up_policy: nil, profile_attributes: ->(_profile) { {} }, deletion_allowed: ->(_user) { true }, external_identities: nil)
        raise ArgumentError, "proof lifetime must be between 60 and 86400 seconds" unless lifetime.is_a?(Numeric) && lifetime.between?(60, 86_400)
        @store, @digest, @cipher, @policy, @password_policy, @trusted_address = store, digest, delivery_cipher, policy, password_policy, trusted_address
        @clock, @random, @lifetime, @notify = clock, random, lifetime, notify
        @sessions, @step_up_policy = sessions, step_up_policy
        @profile_attributes = profile_attributes
        @deletion_allowed = deletion_allowed
        @external_identities = external_identities
      end

      def register(identifier:, password:, profile: {})
        return failure unless valid_new_password?(password)
        register_account(identifier: identifier, password: password, profile: profile)
      end

      def register_external(identifier:, evidence:, profile: {})
        return failure unless @external_identities
        external = @external_identities.call
        register_account(identifier: identifier, password: nil, profile: profile) do |user|
          external.bind_new_account_in_transaction(registration: NewAccount.send(:new, user: user), evidence: evidence)
        end
      rescue ExternalIdentities::EnrollmentRejected
        failure
      end

      def issue(identifier:, purpose:, request_id: @random.uuid)
        return failure unless PURPOSES.include?(purpose.to_s)
        email = normalize(identifier)
        return accepted unless email
        @store.with_user(identifier: email) do |user|
          next if @store.issued?(request_id: request_id)
          next unless @policy.allowed?(user, purpose: purpose)
          recipient = recipient_for(user, purpose.to_s)
          next unless recipient
          issue_in_transaction(user: user, purpose: purpose.to_s, recipient: recipient, request_id: request_id)
        end
        accepted
      end

      def preview(token:, purpose:)
        return failure unless token.is_a?(String) && TOKEN.match?(token) && PURPOSES.include?(purpose.to_s)
        user, record = @store.inspect_token(digest: @digest.digest(token))
        reason = rejection(user, record, purpose: purpose.to_s)
        reason ? Result.failure(reason: reason) : Result.success(user: user, strategy: purpose.to_sym)
      end

      def consume(token:, purpose:, password: nil)
        return failure unless token.is_a?(String) && TOKEN.match?(token) && PURPOSES.include?(purpose.to_s)
        @store.with_token(digest: @digest.digest(token)) do |user, record|
          reason = rejection(user, record, purpose: purpose.to_s)
          next Result.failure(reason: reason) if reason
          now = @clock.now
          case purpose.to_s
          when "confirm"
            pending = user.unconfirmed_email
            if pending && !pending.empty?
              old_address = user.email_address
              @store.promote_address(user: user, digest: address_digest(pending))
              @store.update_account(user: user, email_address: pending, unconfirmed_email: nil, confirmed_at: now)
              @store.revoke_authority(user: user, at: now)
              @notify.call(user: user, kind: :email_changed, at: now, recipient: old_address)
              @notify.call(user: user, kind: :email_changed, at: now, recipient: pending)
            else
              @store.update_account(user: user, confirmed_at: now)
              @store.provision(user: user)
            end
          when "reset_password"
            next failure unless valid_new_password?(password)
            @store.replace_password(user: user, password: password)
            @store.revoke_authority(user: user, at: now)
            @notify.call(user: user, kind: :password_changed, at: now)
          when "unlock"
            @store.update_account(user: user, locked_at: nil, add_auth_locked_until: nil, failed_attempts: 0)
          end
          @store.consume(record: record, at: now)
          Result.success(user: user, strategy: purpose.to_sym)
        end
      rescue Conflict, InvalidPassword
        failure
      end

      def change_email(user:, session:, identifier:)
        email = normalize(identifier)
        return failure unless email
        with_account_change(user: user, session: session, purpose: :change_email) do |account|
          next accepted if email == normalize(account.email_address)
          @store.claim_address(user: account, digest: address_digest(email), address: email, state: "pending")
          @store.update_account(user: account, unconfirmed_email: email)
          issue_in_transaction(user: account, purpose: "confirm", recipient: email)
          accepted
        end
      rescue Conflict
        failure
      end

      def change_password(user:, session:, password:)
        return failure unless valid_new_password?(password)
        with_account_change(user: user, session: session, purpose: :change_password) do |account|
          @store.replace_password(user: account, password: password)
          @store.revoke_authority(user: account, at: @clock.now)
          @notify.call(user: account, kind: :password_changed, at: @clock.now)
          accepted
        end
      rescue InvalidPassword
        failure
      end

      def valid_new_password?(password)
        password.is_a?(String) && password.valid_encoding? && !password.include?("\0") && password.bytesize.between?(1, 1024) && @password_policy.call(password) == true
      end

      def delete_account(user:, session:)
        with_account_change(user: user, session: session, purpose: :delete_account) do |account|
          next failure unless @deletion_allowed.call(account) == true
          @store.revoke_authority(user: account, at: @clock.now)
          @store.delete_account(user: account)
          accepted
        end
      rescue DeletionRejected
        failure
      end

      # The password lifecycle already owns the account transaction and lock.
      def issue_unlock_in_transaction(user:)
        return unless @policy.allowed?(user, purpose: :unlock)
        recipient = recipient_for(user, "unlock")
        issue_in_transaction(user: user, purpose: "unlock", recipient: recipient) if recipient
      end

      private

      def register_account(identifier:, password:, profile:)
        email = normalize(identifier)
        return failure unless email && profile.is_a?(Hash) && profile.length <= 20
        attributes = @profile_attributes.call(profile)
        profile_valid = attributes.is_a?(Hash) && attributes.keys.all? { |name| (name.is_a?(String) || name.is_a?(Symbol)) && !SECURITY_ATTRIBUTES.include?(name.to_s) && !name.to_s.start_with?("add_auth_") }
        raise AddAuth::Error, "registration profile must contain host profile fields only" unless profile_valid
        outcome = @store.create_account(email: email, password: password, profile: attributes) do |user|
          raise Conflict unless @policy.allowed?(user, purpose: :confirm)
          yield user if block_given?
          @store.claim_address(user: user, digest: address_digest(email), address: email, state: "current")
          issue_in_transaction(user: user, purpose: "confirm", recipient: email)
        end
        (outcome == :invalid) ? failure : accepted
      end

      def with_account_change(user:, session:, purpose:)
        outcome = Result.failure(reason: :elevation_required)
        return outcome unless @sessions && @step_up_policy
        authorization = @sessions.with_elevation(user: user, session: session, purpose: purpose, policy: @step_up_policy) do |account|
          outcome = @policy.allowed?(account, purpose: :manage) ? yield(account) : failure
        end
        authorization.success? ? outcome : authorization
      end

      def accepted = Result.success(user: nil, strategy: :account_request)
      def failure = Result.failure(reason: :invalid_credentials)

      def normalize(value)
        return unless value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, 254)
        value = value.strip.downcase
        value if value.match?(/\A[^\s@]+@[^\s@]+\z/) && value.bytesize <= 254
      end

      def address_digest(email) = @digest.digest("account-address:#{normalize(email)}")

      def recipient_for(user, purpose)
        if purpose == "confirm"
          normalize(user.unconfirmed_email.to_s.empty? ? user.email_address : user.unconfirmed_email)
        else
          address = normalize(@trusted_address.call(user))
          address if address == normalize(user.email_address)
        end
      end

      def version(user, purpose)
        @digest.digest(JSON.generate([purpose, user.id, user.email_address, user.unconfirmed_email,
          user.password_digest, user.confirmed_at&.to_f, user.locked_at&.to_f, user.disabled_at&.to_f,
          user.deleted_at&.to_f, user.add_auth_manual_lock]))
      end

      def issue_in_transaction(user:, purpose:, recipient:, request_id: @random.uuid)
        token = "ac1:#{@random.urlsafe_base64(32)}"
        digest = @digest.digest(token)
        expires_at = @clock.now + @lifetime
        payload = @cipher.encrypt(token: JSON.generate(token: token, recipient: recipient, purpose: purpose), digest: digest, expires_at: expires_at)
        @store.replace_pending(user: user, purpose: purpose, digest: digest, request_id: request_id,
          address_digest: address_digest(recipient), account_version: version(user, purpose),
          expires_at: expires_at, delivery_payload: payload, created_at: @clock.now)
      end

      def rejection(user, record, purpose: record&.purpose)
        return :invalid_credentials unless user && record && record.purpose == purpose && PURPOSES.include?(purpose)
        return :consumed_token if record.consumed_at
        return :revoked_token if record.revoked_at
        return :expired_token if record.expires_at <= @clock.now
        return :invalid_credentials unless @policy.allowed?(user, purpose: purpose)
        recipient = recipient_for(user, purpose)
        return :invalid_credentials unless recipient && record.address_digest == address_digest(recipient) && record.account_version == version(user, purpose)
        nil
      end

      def delivery_details(user, record)
        raw = @cipher.decrypt(payload: record.delivery_payload, digest: record.digest)
        return unless raw
        payload = JSON.parse(raw)
        return unless payload["purpose"] == record.purpose && payload["recipient"] == recipient_for(user, record.purpose) &&
          payload["token"].is_a?(String) && @digest.matches?(record.digest, payload["token"])
        {recipient: payload.fetch("recipient"), token: payload.fetch("token"), purpose: record.purpose}
      rescue JSON::ParserError, KeyError
        nil
      end
    end
  end
end
