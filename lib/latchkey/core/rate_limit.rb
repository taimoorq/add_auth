# frozen_string_literal: true

module Latchkey
  module Core
    class RateLimit
      WINDOW = 300
      STAGGER = 60
      DURATION = WINDOW + STAGGER

      def initialize(counter:, clock: Time)
        @counter, @clock = counter, clock
      end

      def call(key:, limit:)
        now = @clock.now.to_i
        # Every rolling five-minute interval fits in at least one of these
        # overlapping six-minute windows. Atomic increments keep that bound
        # across workers without a read/modify/write race or a boundary burst.
        counts = (DURATION / STAGGER).times.map do |phase|
          bucket = (now - phase * STAGGER) / DURATION
          @counter.call(key: "latchkey:rate:v2:#{phase}:#{bucket}:#{key}", expires_in: DURATION)
        end
        unless counts.all? { |count| count.is_a?(Integer) && count.positive? }
          raise Latchkey::Error, "rate limit store must support atomic increment"
        end
        counts.all? { |count| count <= limit }
      end
    end
  end
end
