# frozen_string_literal: true

require "add_auth/rails/stores/account_lock"

module AddAuth
  module Rails
    module Stores
      class Sessions
        def initialize(user_model:, session_model:)
          @users, @sessions = user_model, session_model
          raise ArgumentError, "authentication models must share one connection pool" unless @users.connection_pool.equal?(@sessions.connection_pool)
          @lock = AccountLock.new(@users)
        end

        def with_user(id:, replacing: nil, &block) = @lock.call(id: id, additional_id: replacing&.user_id, &block)

        def with_identifier(identifier:, replacing: nil, &block)
          with_user(id: @users.find_by(email_address: identifier)&.id, replacing: replacing, &block)
        end

        def with_session(digest: nil, id: nil)
          @sessions.uncached do
            criteria = digest ? {token_digest: digest} : {id: id}
            locator = @sessions.find_by(criteria)
            @lock.call(id: locator&.user_id) do |user|
              yield user, user && @sessions.find_by(**criteria, user_id: user.id)
            end
          end
        end

        def create(user:, **attributes)
          raise AddAuth::Error, "session finalization requires an account transaction" unless @users.connection.transaction_open?
          @sessions.create!(**attributes, user_id: user.id)
        end

        def update(row, **attributes) = row.update!(**attributes)

        # Query cutoffs come from Core; Core still authorizes every returned row.
        def list_for_user(user_id:, before:, excluding:, limit:, now:, active_after:, legacy:)
          scope = @sessions.where(user_id: user_id, revoked_at: nil)
          scope = scope.where("id < ?", before) if before
          scope = scope.where.not(id: excluding) if excluding
          scope = scope.where("(expires_at IS NULL OR expires_at > ?) AND (last_seen_at IS NULL OR last_seen_at > ?)", now, active_after)
          scope = scope.where.not(expires_at: nil).where.not(last_seen_at: nil) unless legacy
          scope.order(id: :desc).limit(limit).to_a
        end

        def find_for_user(user_id:, session_id:) = @sessions.find_by(user_id: user_id, id: session_id)

        def find_for_user_in_transaction(user_id:, session_id:)
          raise AddAuth::Error, "session lookup requires an account transaction" unless @users.connection.transaction_open?
          @sessions.uncached { @sessions.find_by(id: session_id, user_id: user_id) }
        end

        def revoke_all_in_transaction(user_id:, at:)
          raise AddAuth::Error, "revocation requires an account transaction" unless @users.connection.transaction_open?
          @sessions.where(user_id: user_id, revoked_at: nil).update_all(revoked_at: at, updated_at: at)
        end
      end
    end
  end
end
