# frozen_string_literal: true

require "add_auth/rails/stores/account_lock"

module AddAuth
  module Rails
    module Migration
      class AccountStore
        FIELDS = {id: :id, email: :email, encrypted_password: :encrypted_password,
                  authority: :add_auth_authority, migration_stamp: :add_auth_migration_stamp,
                  email_address: :email_address, password_digest: :password_digest, scheme: :add_auth_password_scheme}.freeze

        def initialize(user_model:)
          @users = user_model
          @lock = Stores::AccountLock.new(user_model)
          unless @users.primary_key == "id" && (FIELDS.values.map(&:to_s) - @users.column_names).empty?
            raise ArgumentError, "prepare the reviewed User account schema before conversion"
          end
        end

        def source_page(after:, limit:)
          scope = @users.unscoped.order(:id)
          scope = scope.where(@users.arel_table[:id].gt(after)) if after
          scope.limit(limit).pluck(*FIELDS.values).map { |row| FIELDS.keys.zip(row).to_h }
        end

        def with_account(id)
          @lock.call(id: id) { |user| yield(user && FIELDS.to_h { |name, field| [name, user.read_attribute(field)] }) }
        rescue ActiveRecord::RecordNotUnique
          :conflicts
        end

        def prepare(id:, **attributes)
          raise AddAuth::Error, "conversion requires an account transaction" unless @users.connection.transaction_open?
          # Source authority is retained. No callbacks, mail or host provisioning.
          @users.unscoped.where(id: id).update_all(attributes)
        end
      end
    end
  end
end
