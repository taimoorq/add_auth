# frozen_string_literal: true

module AddAuth
  module Rails
    module Stores
      class Maintenance
        def initialize(model:, kind:)
          @model, @kind = model, kind
        end

        def purge_expired(before:, now:, limit:)
          scope = @model.where("expires_at <= ?", before)
          if @kind == :session
            scope = scope.or(@model.where("revoked_at <= ?", before))
          elsif !Core::Maintenance::EXPIRING.key?(@kind)
            scope = without_live_lease(scope, now)
          end
          bounded(scope, limit).delete_all
        end

        def erase_expired_payloads(now:, limit:)
          scope = without_live_lease(@model.where("expires_at <= ?", now).where.not(delivery_payload: nil), now)
          bounded(scope, limit).update_all(delivery_payload: nil)
        end

        def pending_ids(now:, limit:)
          scope = @model.where(revoked_at: nil, delivered_at: nil).where.not(delivery_payload: nil)
            .where("expires_at > ?", now)
          without_live_lease(scope, now).order(:id).limit(limit).pluck(:id)
        end

        private

        def without_live_lease(scope, now)
          scope.where("delivery_lease_until IS NULL OR delivery_lease_until <= ?", now)
        end

        def bounded(scope, limit)
          # Repeat the predicate after selection; a concurrent refresh/lease
          # acquisition protects its row even if it appeared in this ID batch.
          scope.where(id: scope.order(:id).limit(limit).pluck(:id))
        end
      end
    end
  end
end
