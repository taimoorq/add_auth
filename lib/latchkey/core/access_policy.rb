# frozen_string_literal: true

module Latchkey
  module Core
    # Account policy survives feature toggles; disabling passkeys cannot restore
    # weaker access to an account that explicitly adopted strict policy.
    class AccessPolicy
      def initialize(credentials:, passkeys_enabled:, email_enabled:, trusted_recovery_address:)
        @credentials, @passkeys_enabled, @email_enabled = credentials, passkeys_enabled, email_enabled
        @trusted_recovery_address = trusted_recovery_address
      end

      def strict?(user) = user.respond_to?(:latchkey_strict) && user.latchkey_strict == true
      def version(user) = user.respond_to?(:latchkey_policy_version) ? user.latchkey_policy_version : 0

      def sign_in_allowed?(user, method)
        return false if strict?(user) && method.to_sym != :passkey
        case method.to_sym
        when :password then user.respond_to?(:password_digest) && user.password_digest.is_a?(String) && !user.password_digest.empty?
        when :email_link then @email_enabled
        when :passkey then @passkeys_enabled
        else false
        end
      end

      def methods_for(user)
        StepUp::METHODS.select { |method| sign_in_allowed?(user, method) }
      end

      def recovery_address(user)
        address = @trusted_recovery_address.call(user)
        address if address.is_a?(String) && address.valid_encoding? && address.bytesize.between?(3, 254) && address == user.email_address
      end

      def recoverable?(user) = !strict?(user) && @email_enabled && !recovery_address(user).nil?
      def fallback?(user) = !strict?(user) && (sign_in_allowed?(user, :password) || recoverable?(user))

      def credential_current?(user:, id:)
        credential = @credentials.call(id)
        credential && credential.user_id == user.id && !credential.revoked_at
      end

      def session_allowed?(user, row)
        return false if row.respond_to?(:authentication_policy_version) && row.authentication_policy_version != version(user)
        if row.authenticated_with == "passkey"
          return false unless row.authentication_uv && credential_current?(user: user, id: row.authentication_credential_id)
        end
        return true unless strict?(user)
        (row.authenticated_with == "passkey" && row.authentication_uv) ||
          (row.elevated_with == "passkey" && row.elevation_uv && credential_current?(user: user, id: row.elevation_credential_id))
      end
    end
  end
end
