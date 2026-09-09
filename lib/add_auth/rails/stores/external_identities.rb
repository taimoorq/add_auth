# frozen_string_literal: true

require "securerandom"
require "add_auth/rails/stores/account_lock"

module AddAuth
  module Rails
    module Stores
      class ExternalIdentities
        def initialize(user_model:, identity_model:, transaction_model:)
          @users, @identities, @transactions = user_model, identity_model, transaction_model
          unless [identity_model, transaction_model].all? { |model| model.connection_pool.equal?(@users.connection_pool) }
            raise ArgumentError, "authentication models must share one connection pool"
          end
          @lock = AccountLock.new(@users)
        end

        def with_user(id:, &block) = @lock.call(id: id, &block)

        def with_identity(namespace:, replacing: nil)
          @identities.uncached do
            locator = binding(namespace: namespace)
            @lock.call(id: locator&.user_id, additional_id: replacing&.user_id) do |user|
              yield user, user && binding(namespace: namespace)
            end
          end
        end

        # The G3 capability establishes fresh-account provenance. The adapter
        # additionally enforces the exact user model/pool and owning transaction
        # before a pending transaction can be consumed.
        def registration_account(user:)
          return unless @users.connection.transaction_open? && user.is_a?(@users) && user.persisted? && !user.destroyed?
          @users.uncached { @users.find_by(id: user.id) }
        end

        def binding(namespace:) = @identities.find_by(namespace: namespace)
        def binding_for_user(user_id:, id:) = @identities.find_by(user_id: user_id, id: id)
        def bindings(user_id:) = @identities.where(user_id: user_id, revoked_at: nil).to_a

        def bind(user:, evidence:, at:)
          require_transaction!
          # A savepoint contains unique-index failures on PostgreSQL. Account
          # locks serialize same-owner callbacks; the unique namespace index
          # arbitrates different owners without choosing one by email.
          @identities.transaction(requires_new: true) do
            identity = binding(namespace: evidence.namespace)
            if identity
              return unless identity.user_id == user.id
              return identity unless identity.revoked_at
              identity.update!(revoked_at: nil, linked_at: at, credential_version: SecureRandom.hex(16), provenance: evidence.provenance)
              identity
            else
              @identities.create!(user_id: user.id, namespace: evidence.namespace, provider_id: evidence.provider_id,
                issuer: evidence.issuer, audience: evidence.audience, subject: evidence.subject,
                provenance: evidence.provenance, linked_at: at, credential_version: SecureRandom.hex(16))
            end
          end
        rescue ActiveRecord::RecordNotUnique
          nil
        end

        def revoke(identity:, at:)
          require_transaction!
          identity.update!(revoked_at: at, credential_version: SecureRandom.hex(16))
        end

        def invalidate_credentials(user_id:, at:, credential_version:)
          require_transaction!
          # Never move the cutoff backwards if a delayed invalidation arrives.
          @identities.where(user_id: user_id, revoked_at: nil).where("invalidated_at IS NULL OR invalidated_at <= ?", at)
            .update_all(invalidated_at: at, credential_version: credential_version, updated_at: at)
        end

        def create_transaction(**attributes) = @transactions.create!(**attributes)
        def transaction_by_digest(digest:) = @transactions.uncached { @transactions.find_by(digest: digest) }

        def consume_transaction(digest:, at:)
          @transactions.where(digest: digest, consumed_at: nil).where("issued_at <= ? AND expires_at > ?", at, at)
            .update_all(consumed_at: at) == 1
        end

        private

        def require_transaction!
          raise AddAuth::Error, "identity mutation requires an account transaction" unless @users.connection.transaction_open?
        end
      end
    end
  end
end
