# frozen_string_literal: true

module AddAuth
  module Core
    # One bounded, replayable pass. Stores repeat cutoffs at mutation time;
    # returning counts records committed work, never a claim of an empty backlog.
    class Maintenance
      def initialize(stores:, options:, enqueue:, clock: Time)
        @stores, @options, @enqueue, @clock = stores, options, enqueue, clock
        unless options.batch_size.is_a?(Integer) && (1..1000).cover?(options.batch_size)
          raise ArgumentError, "maintenance.batch_size must be an integer from 1 to 1000"
        end
        %i[session email notification].each do |kind|
          value = options.public_send(:"#{kind}_retention")
          valid = value.nil? || (value.is_a?(Numeric) && value.finite? && value >= 0)
          unless valid
            raise ArgumentError, "maintenance.#{kind}_retention must be nonnegative seconds or nil"
          end
        end
      end

      def call
        now, limit = @clock.now, @options.batch_size
        counts = {}
        @stores.each do |kind, store|
          if kind == :ceremony
            counts[:ceremonies_deleted] = store.purge_expired(before: now, now: now, limit: limit)
            next
          end
          retention = @options.public_send(:"#{kind}_retention")
          if kind != :session
            counts[:"#{kind}_payloads_erased"] = store.erase_expired_payloads(now: now, limit: limit)
            ids = store.pending_ids(now: now, limit: limit)
            ids.each { |id| @enqueue.call(kind, id) }
            counts[:"#{kind}_enqueued"] = ids.length
          end
          if retention
            counts[:"#{kind}_deleted"] = store.purge_expired(before: now - retention, now: now, limit: limit)
          end
        end
        counts
      end
    end
  end
end
