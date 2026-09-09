# frozen_string_literal: true

module AddAuth
  module Rails
    module Stores
      class AccountLock
        def initialize(user_model)
          @users = user_model
        end

        def call(id:, additional_id: nil)
          return yield nil unless id
          if @users.connection.transaction_open?
            raise AddAuth::Error, "authentication must own its transaction, not run inside an outer transaction"
          end
          completed = false
          result = nil
          @users.uncached do
            @users.transaction(requires_new: true) do |transaction|
              transaction.after_commit { completed = true }
              # Opposing account switches acquire their locks in the same order.
              accounts = [id, additional_id].compact.uniq.sort_by(&:to_s).map do |account_id|
                current_in_transaction(id: account_id)
              end
              result = yield accounts.compact.find { |account| account.id == id }
            end
          end
          raise AddAuth::Error, "authentication transaction rolled back" unless completed
          result
        end

        # For model save callbacks, whose Active Record transaction already owns
        # the write. All actual row-lock acquisition lives in this adapter.
        def current_in_transaction(id:)
          raise AddAuth::Error, "account row locking requires an owning transaction" unless @users.connection.transaction_open?
          @users.uncached do
            if @users.connection.adapter_name == "SQLite"
              pk = @users.connection.quote_column_name(@users.primary_key)
              @users.unscoped.where(@users.primary_key => id).update_all("#{pk} = #{pk}")
              @users.unscoped.find_by(@users.primary_key => id)
            else
              @users.unscoped.lock.find_by(@users.primary_key => id)
            end
          end
        end
      end
    end
  end
end
