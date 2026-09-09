# frozen_string_literal: true

require "digest"
require "json"

module AddAuth
  module Core
    class ExternalIdentities
      # Only configured server code may supply this verifier. It must validate a
      # live middleware/library result, including issuer, audience, state/nonce
      # and (for reauthentication) auth_time/max_age. A request auth hash is not
      # such a result. Core deliberately contains no protocol or token decoder.
      class Configuration
        attr_reader :id, :issuer, :audience

        def initialize(id:, issuer:, audience:, verifier:, clock: Time)
          @id, @issuer, @audience = [id, issuer, audience].map { |value| self.class.text(value) }
          raise ArgumentError, "a trusted server verifier is required" unless verifier.respond_to?(:call)
          @verifier, @clock = verifier, clock
          freeze
        end

        def self.text(value)
          raise ArgumentError, "invalid external identity field" unless value.is_a?(String) && value.valid_encoding? &&
            value.bytesize.between?(1, 2048) && !value.match?(/[\x00-\x1f\x7f]/)
          value.dup.freeze
        end

        def verify(server_result:, transaction:)
          return unless transaction.is_a?(Pending) && transaction.configuration.equal?(self)
          claims = @verifier.call(server_result: server_result, transaction: transaction)
          return unless claims.is_a?(Hash) && claims[:issuer] == issuer && claims[:audience] == audience
          VerifiedIdentity.send(:new, configuration: self, transaction: transaction,
            subject: self.class.text(claims[:subject]), provenance: self.class.text(claims[:provenance]),
            authenticated_at: claims[:authenticated_at], verified_at: @clock.now)
        rescue ArgumentError
          nil
        end

        def namespace(subject) = ::Digest::SHA256.hexdigest(JSON.generate([id, issuer, audience, subject]))
        def inspect = "#<AddAuth::Core::ExternalIdentities::Configuration [FILTERED]>"
      end

      class Pending
        attr_reader :configuration, :id, :purpose, :user_id, :session_id, :session_digest,
          :policy_version, :issued_at, :expires_at

        def initialize(configuration:, id:, purpose:, user_id:, session_id:, session_digest:, policy_version:, issued_at:, expires_at:)
          @configuration = configuration
          @id, @purpose = id.dup.freeze, purpose.to_sym
          @user_id, @session_id = user_id&.dup&.freeze, session_id&.dup&.freeze
          @session_digest = session_digest&.dup&.freeze
          @policy_version = policy_version
          @issued_at, @expires_at = issued_at.dup.freeze, expires_at.dup.freeze
          freeze
        end
        private_class_method :new

        def inspect = "#<AddAuth::Core::ExternalIdentities::Pending [FILTERED]>"
      end

      class VerifiedIdentity
        attr_reader :configuration, :transaction, :subject, :provenance, :authenticated_at, :verified_at

        def initialize(configuration:, transaction:, subject:, provenance:, authenticated_at:, verified_at:)
          raise ArgumentError, "invalid authentication occurrence time" unless authenticated_at.nil? || authenticated_at.is_a?(Time)
          @configuration, @transaction, @subject, @provenance = configuration, transaction, subject, provenance
          @authenticated_at = authenticated_at&.dup&.freeze
          @verified_at = verified_at.dup.freeze
          freeze
        end
        private_class_method :new

        def provider_id = configuration.id
        def issuer = configuration.issuer
        def audience = configuration.audience
        def transaction_id = transaction.id
        def purpose = transaction.purpose
        def namespace = configuration.namespace(subject)
        def inspect = "#<AddAuth::Core::ExternalIdentities::VerifiedIdentity [FILTERED]>"
      end

      # Session evidence is issued only after locked binding resolution. It is
      # never a StepUp::Evidence merely because the callback was just received.
      class SessionProof
        attr_reader :user_id, :credential_id, :credential_version, :verified_at
        def initialize(user_id:, credential_id:, credential_version:, verified_at:)
          @user_id, @credential_id = user_id, credential_id.to_s.dup.freeze
          @credential_version, @verified_at = credential_version.dup.freeze, verified_at.dup.freeze
          freeze
        end
        private_class_method :new
        def user_verification = false
        def inspect = "#<AddAuth::Core::ExternalIdentities::SessionProof [FILTERED]>"
      end
    end
  end
end
