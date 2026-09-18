# frozen_string_literal: true

module AddAuth
  module Core
    class SessionKey
      UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
      MAX_INTEGER = (2**63) - 1

      def initialize(type:)
        raise ArgumentError, "unsupported session key type" unless %i[integer bigint uuid].include?(type)
        @uuid = type == :uuid
      end

      def parse(value)
        if @uuid
          value.downcase if value.is_a?(String) && value.ascii_only? && UUID.match?(value)
        elsif value.is_a?(Integer)
          value if value.between?(1, MAX_INTEGER)
        elsif value.is_a?(String) && value.ascii_only? && value.match?(/\A[1-9]\d{0,18}\z/)
          integer = value.to_i
          integer if integer <= MAX_INTEGER
        end
      end

      # Stock Rails signed cookies serialize integer IDs as integers, UUIDs as
      # strings. Numeric strings must not broaden the legacy integer bridge.
      def legacy(value)
        parse(value) if @uuid || value.is_a?(Integer)
      end
    end
  end
end
