# frozen_string_literal: true

require "add_auth/rails/stores/delivery_state"

module AddAuth
  module Rails
    module Stores
      class SecurityEvents
        include DeliveryState

        def initialize(user_model:, event_model:)
          @users, @events = user_model, event_model
          raise ArgumentError, "authentication models must share one connection pool" unless @users.connection_pool.equal?(@events.connection_pool)
        end

        def append(user:, **attributes)
          raise AddAuth::Error, "security notifications must join the account transaction" unless @users.current_transaction.open?
          event = @events.create!(**attributes, user_id: user.id)
          @users.current_transaction.after_commit do
            job = ::AddAuth::SecurityNotificationJob.perform_later(event.id)
            raise AddAuth::Error unless job
          rescue
            ActiveSupport::Notifications.instrument("notification_enqueue_failed.add_auth", event_id: event.id)
          end
          event
        end

        def with_token(digest:)
          @events.transaction do
            if @events.connection.adapter_name == "SQLite"
              pk = @events.connection.quote_column_name(@events.primary_key)
              @events.where(digest: digest).update_all("#{pk} = #{pk}")
            end
            @events.uncached { yield nil, @events.lock.find_by(digest: digest) }
          end
        end
      end
    end
  end
end
