# frozen_string_literal: true

module AddAuth
  module Core
    class AccountPolicy
      def initialize(enabled:, eligible: ->(_user) { true }, clock: Time)
        @enabled, @eligible, @clock = enabled, eligible, clock
      end

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
          !!value(user, :confirmed_at) && !value(user, :add_auth_strict)
        else false
        end
      end

      # Only a verified-password result may disclose this to an anonymous client.
      def denial(user)
        return :disabled unless available?(user)
        return unless @enabled
        return :unconfirmed unless value(user, :confirmed_at)
        :locked if locked?(user)
      end

      def locked?(user)
        value(user, :locked_at) && (value(user, :add_auth_manual_lock) || !value(user, :add_auth_locked_until) || value(user, :add_auth_locked_until) > @clock.now)
      end

      private

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
