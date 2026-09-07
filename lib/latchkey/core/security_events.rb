# frozen_string_literal: true

require "json"
require "securerandom"

module Latchkey
  module Core
    class SecurityEvents
      include Delivery

      KINDS = %i[password_changed email_changed passkey_added passkey_removed policy_changed recovery_completed].freeze

      def initialize(store:, digest:, delivery_cipher:, clock: Time, random: SecureRandom)
        @store, @digest, @cipher, @clock, @random = store, digest, delivery_cipher, clock, random
      end

      # Called inside the authentication/account mutation transaction. The
      # encrypted outbox survives an enqueue failure or a process crash.
      def issue(user:, kind:, at:, recipient: user.email_address)
        raise ArgumentError, "unsupported security event" unless KINDS.include?(kind.to_sym)
        unless recipient.is_a?(String) && recipient.valid_encoding? && recipient.bytesize.between?(3, 254) &&
            recipient.include?("@") && !recipient.match?(/[\r\n]/)
          raise ArgumentError, "invalid notification recipient"
        end
        digest = @digest.digest(@random.urlsafe_base64(32))
        expires_at = at + 7 * 86_400
        payload = @cipher.encrypt(token: JSON.generate(recipient: recipient, kind: kind.to_s), digest: digest, expires_at: expires_at)
        @store.append(user: user, kind: kind.to_s, digest: digest, expires_at: expires_at, delivery_payload: payload, created_at: at)
      end

      private

      def rejection(_user, record)
        !record || record.revoked_at || record.expires_at <= @clock.now
      end

      def delivery_details(_user, record)
        raw = @cipher.decrypt(payload: record.delivery_payload, digest: record.digest)
        return unless raw
        value = JSON.parse(raw)
        return unless value["kind"] == record.kind && KINDS.map(&:to_s).include?(record.kind)
        {recipient: value.fetch("recipient"), kind: record.kind}
      rescue JSON::ParserError, KeyError
        nil
      end
    end
  end
end
