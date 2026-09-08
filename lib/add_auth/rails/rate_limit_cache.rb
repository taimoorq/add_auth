# frozen_string_literal: true

module AddAuth
  module Rails
    # Adapter compatibility only; window and admission policy live in Core.
    module RateLimitCache
      INCOMPATIBLE = "Solid Cache cannot provide atomic rate-limit counters; configure rate_limit_store with a separate atomic store"

      def self.validate!(cache)
        if defined?(::SolidCache::Store) && cache.is_a?(::SolidCache::Store)
          raise AddAuth::Error, INCOMPATIBLE
        end
        cache
      end
    end
  end
end
