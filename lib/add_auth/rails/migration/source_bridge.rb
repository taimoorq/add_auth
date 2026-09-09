# frozen_string_literal: true

require "add_auth/core/migration/account_adoption"
require "add_auth/rails/stores/account_lock"

module AddAuth
  module Rails
    module Migration
      # Include after Devise in an expanded, reviewed source model. This does
      # not select routes or retire other host credential readers at cutover.
      module SourceBridge
        extend ActiveSupport::Concern

        included do
          before_save :add_auth_project_source_credentials
        end

        def valid_password?(password)
          Core::Migration::AccountAdoption.source_authority?(self[:add_auth_authority]) && super
        end

        def active_for_authentication?
          Core::Migration::AccountAdoption.source_authority?(self[:add_auth_authority]) && super
        end

        # Devise Lockable increments this counter through update_all before its
        # later save callback. Fence that bypass on the same account row lock.
        def increment_failed_attempts
          self.class.transaction do
            current = Stores::AccountLock.new(self.class).current_in_transaction(id: id)
            raise AddAuth::Error, "source account no longer exists" unless current
            Core::Migration::AccountAdoption.authorize_source_write!(authority: current[:add_auth_authority], changed_fields: [:failed_attempts])
            super
          end
        end

        private

        def add_auth_project_source_credentials
          current = persisted? ? Stores::AccountLock.new(self.class).current_in_transaction(id: id) : self
          raise AddAuth::Error, "source account no longer exists" unless current
          source = %i[email encrypted_password].to_h do |name|
            [name, will_save_change_to_attribute?(name) ? self[name] : current[name]]
          end
          attributes = Core::Migration::AccountAdoption.projection_for_write(**source,
            authority: current[:add_auth_authority], authority_changed: persisted? && will_save_change_to_add_auth_authority?,
            changed_fields: changed_attribute_names_to_save)
          attributes.each { |name, value| self[name] = value }
        end
      end
    end
  end
end
