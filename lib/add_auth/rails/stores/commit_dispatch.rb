# frozen_string_literal: true

module AddAuth
  module Rails
    module Stores
      module CommitDispatch
        module_function

        def enqueue(transaction:, job:, id:, failure_event:, payload:)
          raise AddAuth::Error, "outbox dispatch must join its owning transaction" unless transaction.open?
          transaction.after_commit do
            raise AddAuth::Error unless job.perform_later(id)
          rescue
            notify(event: failure_event, payload: payload)
          end
        end

        def event(transaction:, event:, payload:)
          raise AddAuth::Error, "commit events must join their owning transaction" unless transaction.open?
          transaction.after_commit { notify(event: event, payload: payload) }
        end

        def notify(event:, payload:)
          ActiveSupport::Notifications.instrument(event, payload)
        rescue
          # Optional observers cannot report a committed operation as failed.
          nil
        end
      end
    end
  end
end
