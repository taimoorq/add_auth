# frozen_string_literal: true

require "active_support/message_encryptor"

module Latchkey
  module Rails
    # A pending delivery contains a bearer: encrypt it with a separate key and
    # bind it to its token digest. Never enqueue or log the plaintext argument.
    class DeliveryCipher
      def initialize(key:)
        raise ArgumentError, "delivery key must be 32 bytes" unless key.is_a?(String) && key.bytesize == 32
        @encryptor = ActiveSupport::MessageEncryptor.new(key.dup.freeze,
          cipher: "aes-256-gcm", serializer: :json)
      end

      def encrypt(token:, digest:, expires_at:)
        @encryptor.encrypt_and_sign(token, purpose: purpose(digest), expires_at: expires_at)
      end

      def decrypt(payload:, digest:)
        @encryptor.decrypt_and_verify(payload, purpose: purpose(digest))
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        nil
      end

      def inspect = "#<#{self.class} [FILTERED]>"

      private

      def purpose(digest) = "latchkey.email-delivery.v1:#{digest}"
    end
  end
end
