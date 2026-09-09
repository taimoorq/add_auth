# frozen_string_literal: true

require "add_auth/rails/stores/account_lock"

module AddAuth
  module Rails
    module Stores
      class MobileHandoffs
        def initialize(user_model:, handoff_model:, session_model:)
          @users, @handoffs = user_model, handoff_model
          unless [handoff_model, session_model].all? { |model| model.connection_pool.equal?(@users.connection_pool) }
            raise ArgumentError, "mobile authentication models must share one connection pool"
          end
          @lock = AccountLock.new(@users)
        end

        def create_pending(**attributes)
          @handoffs.transaction(requires_new: true) { @handoffs.create!(**attributes) }
        rescue ActiveRecord::RecordNotUnique
          nil
        end

        def by_external_digest(digest:) = @handoffs.uncached { @handoffs.find_by(external_digest: digest) }

        def issue(row:, **attributes)
          require_transaction!
          @handoffs.where(id: row.id, digest: nil, consumed_at: nil, user_id: nil).update_all(**attributes) == 1
        end

        def with_code(digest:)
          @handoffs.uncached do
            locator = @handoffs.find_by(digest: digest)
            @lock.call(id: locator&.user_id) do |user|
              yield user, user && @handoffs.find_by(digest: digest, user_id: user.id)
            end
          end
        end

        def consume(row:, at:)
          require_transaction!
          @handoffs.where(id: row.id, user_id: row.user_id, consumed_at: nil).where("expires_at > ?", at)
            .update_all(consumed_at: at) == 1
        end

        private

        def require_transaction!
          raise AddAuth::Error, "mobile handoff requires an account transaction" unless @users.connection.transaction_open?
        end
      end
    end
  end
end
