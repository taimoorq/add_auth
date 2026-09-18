# frozen_string_literal: true

require "base64"
require "json"
require "time"

module AddAuth
  module Core
    class SessionCursor
      def initialize(key:)
        @key = key
      end

      def encode(row)
        "sc1:" + Base64.urlsafe_encode64(JSON.generate([row.created_at.utc.iso8601(6), row.id]), padding: false)
      end

      def decode(value)
        # Retain links issued by releases with integer-only pagination.
        legacy = @key.parse(value)
        return {legacy_id: legacy} if legacy.is_a?(Integer)
        return unless value.is_a?(String) && value.ascii_only? && value.bytesize <= 256 && value.match?(/\Asc1:[A-Za-z0-9_-]+\z/)

        fields = JSON.parse(Base64.urlsafe_decode64(value.delete_prefix("sc1:")))
        return unless fields.is_a?(Array) && fields.length == 2
        timestamp, id = fields
        return unless timestamp.is_a?(String) && timestamp.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\z/)
        id = @key.parse(id)
        return unless id
        time = Time.iso8601(timestamp)
        return unless time.year.positive? && time.utc.iso8601(6) == timestamp
        {created_at: time, id: id}
      rescue ArgumentError, JSON::ParserError
        nil
      end
    end
  end
end
