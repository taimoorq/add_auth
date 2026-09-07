# frozen_string_literal: true

require "latchkey/rails/stores/account_lock"

module Latchkey
  module Rails
    module Stores
      class Passkeys
        def initialize(user_model:, session_model:, credential_model:, ceremony_model:, token_model:)
          @users, @sessions, @credentials, @ceremonies = user_model, session_model, credential_model, ceremony_model
          @tokens = token_model
          unless [@sessions, @credentials, @ceremonies, @tokens].all? { |model| model.connection_pool.equal?(@users.connection_pool) }
            raise ArgumentError, "authentication models must share one connection pool"
          end
          @lock = AccountLock.new(@users)
        end

        def with_user(id:, &block) = @lock.call(id: id, &block)
        def credentials(user:) = @credentials.where(user_id: user.id, revoked_at: nil).order(:created_at).to_a
        def credential(id:) = @credentials.find_by(external_id: id)
        def update(record, **attributes) = record.update!(**attributes)
        def create_ceremony(**attributes) = @ceremonies.create!(**attributes)

        def with_ceremony(digest:, user_id:, replacing: nil)
          @lock.call(id: user_id, additional_id: replacing&.user_id) do |user|
            # Anonymous assertions for different accounts can share a challenge;
            # locking only those different accounts would not prevent replay.
            record = @ceremonies.lock.find_by(digest: digest) if user
            yield user, record
          end
        end

        def create_credential(user:, **attributes)
          @credentials.transaction(requires_new: true) do
            @credentials.create!(**attributes, user_id: user.id)
          end
        rescue ActiveRecord::RecordNotUnique
          nil
        end

        def cancel(digest:)
          @ceremonies.transaction do
            if @ceremonies.connection.adapter_name == "SQLite"
              pk = @ceremonies.connection.quote_column_name(@ceremonies.primary_key)
              @ceremonies.where(digest: digest).update_all("#{pk} = #{pk}")
            end
            @ceremonies.uncached { yield @ceremonies.lock.find_by(digest: digest) }
          end
        end

        def revoke_other_sessions(user:, except:, at:)
          @sessions.where(user_id: user.id, revoked_at: nil).where.not(id: except.id).update_all(revoked_at: at)
        end

        def invalidate_proofs(user:, at:)
          @tokens.where(user_id: user.id, consumed_at: nil, revoked_at: nil).update_all(revoked_at: at, delivery_payload: nil)
          @ceremonies.where(user_id: user.id, consumed_at: nil).update_all(consumed_at: at)
          @sessions.where(user_id: user.id).update_all(elevated_at: nil, elevation_version: nil, elevation_expires_at: nil)
        end
      end
    end
  end
end
