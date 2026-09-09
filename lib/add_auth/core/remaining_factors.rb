# frozen_string_literal: true

module AddAuth
  module Core
    # Evaluate against a reloaded account under the credential mutation lock.
    # Counts must include only this account's live credentials. Feature flags
    # and method labels alone do not establish a usable remaining factor.
    class RemainingFactors
      def initialize(access_policy:, passkey_count:, password_available:)
        @access, @passkey_count, @password_available = access_policy, passkey_count, password_available
      end

      def call(user)
        return true if @access.sign_in_allowed?(user, :passkey) && positive_count?(@passkey_count.call(user))
        return true if @access.recoverable?(user)
        @access.sign_in_allowed?(user, :password) && @password_available.call(user) == true
      end

      private

      def positive_count?(value) = value.is_a?(Integer) && value.positive?
    end
  end
end
