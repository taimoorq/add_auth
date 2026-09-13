# frozen_string_literal: true

module AddAuth
  module Core
    class AccountPolicy
      def initialize(enabled:, eligible: ->(_user) { true }, clock: Time, confirmation_required: true, reset_unconfirmed: false)
        unless [confirmation_required, reset_unconfirmed].all? { |value| value == true || value == false }
          raise ArgumentError, "confirmation_required and reset_unconfirmed must be true or false"
        end
        raise ArgumentError, "reset_unconfirmed requires optional confirmation" if confirmation_required && reset_unconfirmed
        @enabled, @eligible, @clock = enabled, eligible, clock
        @confirmation_required, @reset_unconfirmed = confirmation_required, reset_unconfirmed
      end

      def confirmation_required? = @confirmation_required

      def unconfirmed_reset?(user)
        @enabled && @reset_unconfirmed && !value(user, :confirmed_at) &&
          password_account?(user)
      end

      def trusted_address?(user) = !@enabled || !!value(user, :confirmed_at)

      def allowed?(user, purpose: :sign_in)
        return denial(user).nil? if %i[sign_in manage].include?(purpose.to_sym)
        return false unless available?(user)
        return true unless @enabled
        case purpose.to_sym
        when :confirm
          !value(user, :confirmed_at) || !value(user, :unconfirmed_email).to_s.empty?
        when :unlock
          locked?(user) && !value(user, :add_auth_manual_lock)
        when :reset_password
          (!!value(user, :confirmed_at) || unconfirmed_reset?(user)) && !value(user, :add_auth_strict)
        else false
        end
      end

      # Only a verified-password result may disclose this to an anonymous client.
      def denial(user)
        return :disabled unless available?(user)
        return unless @enabled
        return :unconfirmed if !value(user, :confirmed_at) && (confirmation_required? || !password_account?(user))
        :locked if locked?(user)
      end

      def locked?(user)
        value(user, :locked_at) && (value(user, :add_auth_manual_lock) || !value(user, :add_auth_locked_until) || value(user, :add_auth_locked_until) > @clock.now)
      end

      private

      def password_account?(user)
        value(user, :password_digest).is_a?(String) && !user.password_digest.empty?
      end

      def available?(user)
        user && @eligible.call(user) == true &&
          (!user.respond_to?(:add_auth_authority) || user.add_auth_authority == "add_auth") &&
          (!@enabled || !(value(user, :disabled_at) || value(user, :deleted_at)))
      end

      def value(user, name)
        user.public_send(name) if user.respond_to?(name)
      end
    end
  end
end
