# frozen_string_literal: true

require "json"
require "active_support/message_encryptor"

module AddAuth
  module Rails
    # Bounded transport storage for the form collected before provider consent.
    # This grants no identity/account authority: G3/G4 still consume the exact
    # verified enrollment transaction inside the new-account transaction.
    class ProviderEnrollment
      MAX_BYTES = 4096

      def initialize(model:, digest:, key:)
        @model, @digest = model, digest
        @cipher = ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm", serializer: :json)
      end

      def write(pending:, identifier:, profile:)
        return false unless enrollment?(pending) && bounded_profile?(profile) && identifier.is_a?(String)
        payload = {"identifier" => identifier, "profile" => profile}
        return false unless JSON.generate(payload).bytesize <= MAX_BYTES
        ciphertext = @cipher.encrypt_and_sign(payload, purpose: purpose(pending), expires_at: pending.expires_at)
        row(pending).where(enrollment_payload: nil).update_all(enrollment_payload: ciphertext) == 1
      rescue JSON::GeneratorError, EncodingError
        false
      end

      def read(pending:)
        return unless enrollment?(pending)
        ciphertext = row(pending).pick(:enrollment_payload)
        return unless ciphertext.is_a?(String) && ciphertext.bytesize <= MAX_BYTES * 3
        payload = @cipher.decrypt_and_verify(ciphertext, purpose: purpose(pending))
        return unless payload.is_a?(Hash) && payload["identifier"].is_a?(String) && bounded_profile?(payload["profile"])
        {identifier: payload.fetch("identifier"), profile: payload.fetch("profile").symbolize_keys}
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        nil
      end

      def erase(pending:)
        row(pending).update_all(enrollment_payload: nil) if enrollment?(pending)
      end

      private

      def enrollment?(pending)
        pending.is_a?(Core::ExternalIdentities::Pending) && pending.purpose == Core::ExternalIdentities::ENROLL
      end

      def bounded_profile?(profile)
        profile.is_a?(Hash) && profile.size <= 20 && profile.all? do |name, value|
          (name.is_a?(String) || name.is_a?(Symbol)) && name.to_s.valid_encoding? && name.to_s.bytesize.between?(1, 64) &&
            (value.nil? || value == true || value == false || (value.is_a?(String) && value.valid_encoding? && value.bytesize <= 2048))
        end
      end

      def purpose(pending) = "add_auth.external-enrollment:#{@digest.digest(pending.id)}"
      def row(pending) = @model.where(digest: @digest.digest(pending.id))
    end
  end
end
