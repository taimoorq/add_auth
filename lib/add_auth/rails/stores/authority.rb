# frozen_string_literal: true

module AddAuth
  module Rails
    module Stores
      # One persistence implementation for retiring outstanding account authority.
      # Core chooses the event, account and time; callers own the account lock.
      class Authority
        def initialize(user_model:, session_model:, token_models: [], ceremony_models: [], credential_models: [], external_invalidator: nil)
          @external_invalidator = external_invalidator
          @users, @sessions, @tokens, @ceremonies, @credentials = user_model, session_model, token_models, ceremony_models, credential_models
          unless [session_model, *token_models, *ceremony_models, *credential_models].all? { |model| model.connection_pool.equal?(user_model.connection_pool) }
            raise ArgumentError, "authentication models must share one connection pool"
          end
        end

        def revoke(user_id:, at:)
          raise AddAuth::Error, "authority revocation requires an account transaction" unless @users.connection.transaction_open?
          @external_invalidator&.call(user_id: user_id, at: at)
          @sessions.where(user_id: user_id, revoked_at: nil).update_all(revoked_at: at)
          @tokens.each { |model| model.where(user_id: user_id, consumed_at: nil, revoked_at: nil).update_all(revoked_at: at, delivery_payload: nil) }
          @ceremonies.each { |model| model.where(user_id: user_id, consumed_at: nil).update_all(consumed_at: at) }
          @credentials.each { |model| model.where(user_id: user_id, revoked_at: nil).update_all(revoked_at: at) }
        end
      end
    end
  end
end
