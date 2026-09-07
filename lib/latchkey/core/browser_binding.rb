# frozen_string_literal: true

require "securerandom"

module Latchkey
  module Core
    # A browser secret is transport state, never identity or stronger proof.
    class BrowserBinding
      def initialize(digest:)
        @digest = digest
      end

      def generate = SecureRandom.urlsafe_base64(32)

      def digest(secret)
        @digest.digest("browser:#{secret}") if valid?(secret)
      end

      def matches?(stored, secret)
        valid?(secret) && stored.is_a?(String) && @digest.matches?(stored, "browser:#{secret}")
      end

      def valid?(secret)
        secret.is_a?(String) && secret.bytesize == 43 && secret.ascii_only? && /\A[A-Za-z0-9_-]{43}\z/.match?(secret)
      end
    end
  end
end
