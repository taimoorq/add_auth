# frozen_string_literal: true

module Latchkey
  module Core
    # Shared leased-delivery state machine. The including strategy supplies
    # rejection(user, record) and delivery_details(user, record); the store owns
    # locking and persistence. Transport always runs after this lock returns.
    module Delivery
      def claim_delivery(digest:)
        @store.with_token(digest: digest) do |user, record|
          next if rejection(user, record) || record.delivery_payload.nil? || record.delivered_at ||
            (record.delivery_lease_until && record.delivery_lease_until > @clock.now)
          details = delivery_details(user, record)
          next unless details
          key = @random.hex(16)
          @store.lease(record: record, key: key, until_time: @clock.now + 300)
          details.merge(lease: key)
        end
      end

      def delivery_failed(digest:, lease: nil)
        @store.with_token(digest: digest) do |user, record|
          next if lease && record && record.delivery_lease_key != lease
          @store.revoke(record: record, at: @clock.now) unless rejection(user, record)
        end
        nil
      end

      def delivery_succeeded(digest:, lease:)
        finish_delivery(digest: digest, lease: lease, outcome: :delivered)
      end

      def finish_delivery(digest:, lease:, outcome:)
        raise ArgumentError, "unsupported delivery outcome" unless %i[delivered cancelled].include?(outcome)
        return false unless lease.is_a?(String) && !lease.empty?
        @store.with_token(digest: digest) do |_user, record|
          next false unless record && record.delivery_lease_key == lease
          if outcome == :delivered
            @store.delivered(record: record, at: @clock.now)
          else
            @store.revoke(record: record, at: @clock.now)
            @store.lease(record: record, key: nil, until_time: nil)
          end
          true
        end
      end

      def delivery_retry(digest:, lease:)
        @store.with_token(digest: digest) do |_user, record|
          @store.lease(record: record, key: nil, until_time: nil) if record && record.delivery_lease_key == lease
        end
      end
    end
  end
end
