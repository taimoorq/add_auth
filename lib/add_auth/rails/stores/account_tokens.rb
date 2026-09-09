# frozen_string_literal: true

require "add_auth/rails/stores/email_tokens"
require "add_auth/rails/stores/commit_dispatch"
require "add_auth/rails/stores/account_credentials"

module AddAuth
  module Rails
    module Stores
      class AccountTokens < EmailTokens
        def initialize(user_model:, token_model:, session_model:, address_model:, authority:, provision:, delete_account: ->(user) { user.destroy! })
          super(user_model: user_model, token_model: token_model, session_model: session_model)
          raise ArgumentError, "address claims must share the account connection pool" unless address_model.connection_pool.equal?(user_model.connection_pool)
          @addresses, @authority, @provision = address_model, authority, provision
          @delete_account = delete_account
          @account_credentials = AccountCredentials.new(user_model: user_model, authority: authority)
        end

        def create_account(email:, password:, profile: {})
          raise AddAuth::Error, "registration must own its transaction" if @users.connection.transaction_open?
          completed = false
          @users.transaction do |transaction|
            transaction.after_commit { completed = true }
            user = @users.new(profile)
            user.email_address = email
            user.password = password
            user.add_auth_authority = "add_auth"
            user.save!
            yield user
          end
          raise AddAuth::Error, "registration transaction rolled back" unless completed
          :created
        rescue ActiveRecord::RecordNotUnique, Core::AccountLifecycle::Conflict
          :duplicate
        rescue ActiveRecord::RecordInvalid => error
          (error.record.errors.attribute_names - [:email_address]).empty? ? :duplicate : :invalid
        end

        def replace_pending(**attributes)
          raise AddAuth::Error, "account proof must join its owning transaction" unless @users.current_transaction.open?
          record = super
          CommitDispatch.enqueue(transaction: @users.current_transaction, job: ::AddAuth::AccountDeliveryJob,
            id: record.id, failure_event: "account_enqueue_failed.add_auth", payload: {issuance_id: record.id})
          record
        end

        def claim_address(user:, digest:, address:, state:)
          raise Core::AccountLifecycle::Conflict if @users.where(email_address: address).where.not(id: user.id).exists?
          @addresses.where(user_id: user.id, state: state).where.not(digest: digest).delete_all
          existing = @addresses.find_by(digest: digest)
          if existing
            raise Core::AccountLifecycle::Conflict unless existing.user_id == user.id && existing.state == state
          else
            @addresses.create!(user_id: user.id, digest: digest, state: state)
          end
        rescue ActiveRecord::RecordNotUnique
          raise Core::AccountLifecycle::Conflict
        end

        def promote_address(user:, digest:)
          pending = @addresses.find_by!(user_id: user.id, digest: digest, state: "pending")
          @addresses.where(user_id: user.id, state: "current").delete_all
          pending.update!(state: "current")
        end

        def inspect_token(digest:)
          @tokens.uncached do
            record = @tokens.find_by(digest: digest)
            [record && @users.find_by(id: record.user_id), record]
          end
        end

        def update_account(user:, **attributes)
          # Core owns notices and invalidation for this transition. Avoid firing
          # a second independent model callback for the same committed change.
          @account_credentials.update_account(user: user, **attributes)
        end

        def replace_password(user:, password:)
          @account_credentials.replace_password(user: user, password: password)
        end

        def revoke_authority(user:, at:) = @authority.revoke(user_id: user.id, at: at)
        def provision(user:) = @provision.call(user)

        def delete_account(user:)
          raise AddAuth::Error, "account deletion requires its owning transaction" unless @users.connection.transaction_open?
          @delete_account.call(user)
          raise Core::AccountLifecycle::DeletionRejected if @users.unscoped.exists?(id: user.id)
        rescue ActiveRecord::RecordNotDestroyed, ActiveRecord::InvalidForeignKey
          raise Core::AccountLifecycle::DeletionRejected, cause: nil
        end
      end
    end
  end
end
