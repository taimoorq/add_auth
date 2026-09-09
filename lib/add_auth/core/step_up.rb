# frozen_string_literal: true

module AddAuth
  module Core
    # Evidence is issued by a trusted verifier, never deserialized from a client.
    # A grant retains that verifier's current policy and the proof's original age.
    class StepUp
      METHODS = %i[password email_link passkey external_identity].freeze

      class Evidence
        attr_reader :user_id, :session_id, :method, :verified_at, :credential_id,
          :user_verification, :session_digest, :credential_version

        def initialize(user_id:, session_id:, method:, verified_at:, credential_id: nil,
          user_verification: false, session_digest: nil, credential_version: nil)
          @user_id, @session_id, @method, @verified_at = user_id, session_id, method.to_sym, verified_at
          @credential_id, @user_verification = credential_id, user_verification == true
          @session_digest, @credential_version = session_digest&.dup&.freeze, credential_version&.dup&.freeze
          @verified_at = verified_at.dup.freeze
          @credential_id = credential_id&.dup&.freeze
          freeze
        end

        def strong?
          method == :passkey && user_verification && credential_id.is_a?(String) && !credential_id.empty?
        end

        def inspect = "#<AddAuth::Core::StepUp::Evidence [FILTERED]>"
      end

      class ExternalEvidence < Evidence
        attr_reader :purpose
        def initialize(purpose:, **attributes)
          @purpose = purpose.to_sym
          super(**attributes)
        end
        private_class_method :new
      end

      class Grant
        attr_reader :purpose, :expires_at
        def initialize(evidence:, purpose:, expires_at:, policy:)
          @evidence, @purpose, @expires_at, @policy = evidence, purpose, expires_at, policy
          freeze
        end

        %i[user_id session_id method verified_at credential_id user_verification session_digest credential_version].each do |attribute|
          define_method(attribute) { @evidence.public_send(attribute) }
        end

        def valid_for?(user_id:, session_id:, purpose:, now:, user: nil, session_digest: nil)
          user && user.id == user_id && @evidence.user_id == user_id && @evidence.session_id == session_id &&
            purpose.to_sym == @purpose && @evidence.session_digest == session_digest &&
            now.is_a?(Time) && now >= verified_at && now < @expires_at &&
            @policy.current?(user: user, purpose: @purpose, evidence: @evidence)
        end

        def inspect = "#<AddAuth::Core::StepUp::Grant purpose=#{purpose.inspect} method=#{method.inspect}>"
      end

      class Rule
        attr_reader :methods, :require_passkey, :return_to, :label, :reauthentication
        def initialize(methods:, require_passkey: false, return_to: "/", label: "Continue", reauthentication: true)
          @reauthentication = reauthentication == true
          @methods = Array(methods).map(&:to_sym).uniq.freeze
          raise ArgumentError, "unsupported step-up method" unless (@methods - METHODS).empty?
          raise ArgumentError, "return_to must be a safe local GET path" unless Sessions.safe_return(return_to)
          @return_to, @label = return_to.dup.freeze, label.to_s.dup.freeze
          @require_passkey = require_passkey == true
          freeze
        end
      end

      def initialize(purposes:, fresh_for: 600, strong_for: 300, clock: Time, credential_current: nil, password_version: ->(user) { user.password_digest }, methods_available: ->(_user) { METHODS })
        unless [fresh_for, strong_for].all? { |value| value.is_a?(Numeric) && value.finite? && value.positive? }
          raise ArgumentError, "step-up windows must be positive"
        end
        raise ArgumentError, "strong_for must not exceed fresh_for" if strong_for > fresh_for
        @purposes = purposes.transform_keys(&:to_sym).transform_values do |rule|
          rule.is_a?(Rule) ? rule : Rule.new(**rule)
        end.freeze
        @fresh_for, @strong_for, @clock, @credential_current = fresh_for, strong_for, clock, credential_current
        @password_version, @methods_available = password_version, methods_available
      end

      def rule_for(purpose)
        return unless purpose.is_a?(String) || purpose.is_a?(Symbol)
        return if purpose.to_s.bytesize > 64
        @purposes[purpose.to_sym]
      end

      def reauthentication_rule_for(purpose)
        rule = rule_for(purpose)
        rule if rule&.reauthentication
      end

      def return_to(purpose) = rule_for(purpose)&.return_to || "/"

      def methods_for(user:, purpose:)
        rule = rule_for(purpose)
        return [] unless user && rule
        available = rule.methods & @methods_available.call(user)
        rule.require_passkey ? available & [:passkey] : available
      end

      def password_version(user) = @password_version.call(user)

      def authorize(user:, session_id:, purpose:, evidence:)
        now = @clock.now
        unless evidence.is_a?(Evidence) && user && evidence.user_id == user.id &&
            evidence.session_id == session_id && evidence.verified_at.is_a?(Time) && now.is_a?(Time) &&
            current?(user: user, purpose: purpose, evidence: evidence)
          return Result.failure(reason: :elevation_required)
        end
        window = evidence.strong? ? @strong_for : @fresh_for
        return Result.failure(reason: :elevation_required) unless evidence.verified_at <= now && now < evidence.verified_at + window

        grant = Grant.new(evidence: evidence, purpose: purpose.to_sym,
          expires_at: evidence.verified_at + window, policy: self)
        Result.success(user: user, strategy: :step_up, credential: grant)
      end

      def current?(user:, purpose:, evidence:)
        rule = rule_for(purpose)
        return false unless rule && methods_for(user: user, purpose: purpose).include?(evidence.method)
        return false if rule.require_passkey && !evidence.strong?
        return false unless evidence.session_digest.is_a?(String) && !evidence.session_digest.empty?
        return false if evidence.method == :passkey && !evidence.strong?
        if evidence.method == :external_identity
          return false unless evidence.is_a?(ExternalEvidence) && evidence.purpose == purpose.to_sym
        end
        if evidence.method == :password
          return false unless evidence.credential_version.is_a?(String) && !evidence.credential_version.empty?
          return false unless user.respond_to?(:password_digest) && password_version(user) == evidence.credential_version
          return true unless @credential_current
        end
        @credential_current && @credential_current.call(user: user, evidence: evidence) == true
      end
    end
  end
end
