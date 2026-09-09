# frozen_string_literal: true

module AddAuth
  module Rails
    module UserLifecycle
      extend ActiveSupport::Concern

      included do
        before_update :add_auth_validate_account_write
        after_update :add_auth_invalidate_proofs
      end

      private

      def add_auth_validate_account_write
        Core::AccountLifecycle.validate_host_write!(changes: changes_to_save, enabled: AddAuth.configuration.lifecycle.enabled)
      end

      def add_auth_invalidate_proofs
        return unless Core::Intake.revoke_after_change?(saved_changes)
        now = Time.current
        kind = Core::Intake.notification_after_change(saved_changes)
        if AddAuth.configuration.notifications.enabled && kind
          Runtime.security_events.issue(user: self, kind: kind, at: now)
          if saved_change_to_email_address? && email_address_before_last_save != email_address
            Runtime.security_events.issue(user: self, kind: :email_changed, at: now, recipient: email_address_before_last_save)
          end
        end
        Runtime.authority.revoke(user_id: id, at: now)
      end
    end
  end
end
