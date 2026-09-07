# frozen_string_literal: true

require "latchkey/rails/stores/account_lock"

module Latchkey
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
          raise Latchkey::Error, "session finalization requires an account transaction" unless @users.connection.transaction_open?
          @sessions.create!(**attributes, user_id: user.id)
        end

        def update(row, **attributes) = row.update!(**attributes)

        def list_for_user(user_id:)
          @sessions.where(user_id: user_id).order(last_seen_at: :desc, created_at: :desc).to_a
        end

        def find_for_user_in_transaction(user_id:, session_id:)
          raise Latchkey::Error, "session lookup requires an account transaction" unless @users.connection.transaction_open?
          @sessions.uncached { @sessions.find_by(id: session_id, user_id: user_id) }
        end

        def revoke_all_in_transaction(user_id:, at:)
          raise Latchkey::Error, "revocation requires an account transaction" unless @users.connection.transaction_open?
          @sessions.where(user_id: user_id, revoked_at: nil).update_all(revoked_at: at, updated_at: at)
        end
      end
    end
  end
end
