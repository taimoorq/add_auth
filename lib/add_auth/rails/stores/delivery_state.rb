# frozen_string_literal: true

module AddAuth
  module Rails
    module Stores
      module DeliveryState
        def revoke(record:, at:)
          record.update!(revoked_at: at, delivery_payload: nil)
        end

        def lease(record:, key:, until_time:)
          record.update!(delivery_lease_key: key, delivery_lease_until: until_time)
        end

        def delivered(record:, at:)
          record.update!(delivered_at: at, delivery_payload: nil, delivery_lease_key: nil, delivery_lease_until: nil)
        end
      end
    end
  end
end
