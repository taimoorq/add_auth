# frozen_string_literal: true

module AddAuth
  module Rails
    module Stores
      class AccountCredentials
        def initialize(user_model:, authority:)
          @users, @authority = user_model, authority
        end

        def update_account(user:, **attributes)
          raise AddAuth::Error, "credential changes require an account transaction" unless @users.connection.transaction_open?
          user.update_columns(attributes)
          user.reload
        rescue ActiveRecord::RecordNotUnique
          raise Core::AccountLifecycle::Conflict
        end

        def replace_password(user:, password:)
          raise AddAuth::Error, "credential changes require an account transaction" unless @users.connection.transaction_open?
          user.password = password
          unless user.valid?
            user.reload
            raise Core::AccountLifecycle::InvalidPassword
          end
          persist_password(user: user, digest: user.password_digest)
        end

        def rehash_password(user:, password:)
          fresh = @users.new(password: password)
          persist_password(user: user, digest: fresh.password_digest)
        end

        def revoke_authority(user:, at:) = @authority.revoke(user_id: user.id, at: at)

        private

        def persist_password(user:, digest:)
          update_account(user: user, password_digest: digest, add_auth_password_scheme: "rails")
        end
      end
    end
  end
end
