# frozen_string_literal: true

module AddAuth
  module Rails
    module UserLifecycle
      extend ActiveSupport::Concern

      included do
        after_update :add_auth_invalidate_proofs
      end

      private

      def add_auth_invalidate_proofs
        return unless Core::Intake.revoke_after_change?(saved_changes)
        now = Time.current
        if AddAuth.configuration.notifications.enabled
          kind = saved_changes.key?("password_digest") ? :password_changed : :email_changed
          Runtime.security_events.issue(user: self, kind: kind, at: now)
          if saved_change_to_email_address? && email_address_before_last_save != email_address
            Runtime.security_events.issue(user: self, kind: :email_changed, at: now, recipient: email_address_before_last_save)
          end
        end
        if defined?(::AddAuthCeremony) && ::AddAuthCeremony.table_exists?
          ::AddAuthCeremony.where(user_id: id, consumed_at: nil).update_all(consumed_at: now)
        end
        sessions.where(revoked_at: nil).update_all(revoked_at: now)
        if defined?(::AddAuthSignInToken) && ::AddAuthSignInToken.table_exists?
          ::AddAuthSignInToken.where(user_id: id, consumed_at: nil, revoked_at: nil)
            .update_all(revoked_at: now, delivery_payload: nil)
        end
      end
    end
  end
end
