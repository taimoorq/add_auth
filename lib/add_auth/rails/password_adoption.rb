# frozen_string_literal: true

require "add_auth/core/passwords/legacy_bcrypt"
require "add_auth/core/passwords/credential"

module AddAuth
  module Rails
    # Include after has_secure_password. Rails owns new assignment and lookup;
    # Core chooses exactly one verifier for the persisted credential profile.
    module PasswordAdoption
      extend ActiveSupport::Concern

      included do
        self.filter_attributes += [:add_auth_password_scheme]
        before_save :add_auth_retire_legacy_password
      end

      def authenticate_password(password)
        result = Core::Passwords::Credential.new(legacy_verifier: AddAuth.configuration.legacy_password_verifier)
          .authenticate(user: self, password: password, current: ->(value) { super(value) })
        result.success? ? result.user : false
      end

      def authenticate(password) = authenticate_password(password)

      private

      def add_auth_retire_legacy_password
        # A host's ordinary password assignment replaces the legacy credential.
        # Direct migration copies do not set the virtual plaintext attribute.
        self.add_auth_password_scheme = Core::Passwords::Credential.scheme_after_assignment(
          scheme: add_auth_password_scheme, password: password, digest_changed: will_save_change_to_password_digest?
        )
      end
    end
  end
end
