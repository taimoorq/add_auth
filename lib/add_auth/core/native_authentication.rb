# frozen_string_literal: true

require "securerandom"

module AddAuth
  module Core
    class NativeAuthentication
      Challenge = Struct.new(:id, :nonce, :expires_at) do
        def inspect = "#<AddAuth::Core::NativeAuthentication::Challenge [FILTERED]>"
      end

      def initialize(external_identities:, profile:, providers:, intake:, verify:, accounts: nil)
        @external, @profile, @providers, @intake, @verify = external_identities, profile, providers, intake, verify
        unless providers.is_a?(Hash) && providers.all? { |client_id, provider| profile&.client?(client_id) && provider.is_a?(ExternalIdentities::Configuration) }
          raise ArgumentError, "register a native provider configuration for each supported client"
        end
        @providers = providers.dup.freeze
        @accounts = accounts
      end

      def start(client_id:, ip:, challenge_token: nil, intent: "sign_in")
        admitted = @intake.anonymous(ip: ip, action: (intent == "enroll") ? :register : :provider, challenge_token: challenge_token)
        return failure(admitted) if admitted.is_a?(Symbol)
        provider = @providers[client_id]
        return failure unless @profile&.client?(client_id) && provider
        purpose = {"sign_in" => ExternalIdentities::NATIVE, "enroll" => ExternalIdentities::NATIVE_ENROLL}[intent]
        return failure unless purpose
        return failure if intent == "enroll" && !@accounts
        nonce = SecureRandom.urlsafe_base64(32)
        result = @external.begin_transaction(configuration_id: provider.id, browser_secret: nonce, purpose: purpose,
          binding_context: context(client_id))
        return result unless result.success?
        Result.success(user: nil, strategy: :external_identity,
          credential: Challenge.new(id: result.credential.id, nonce: nonce, expires_at: result.credential.expires_at))
      end

      def complete(client_id:, challenge_id:, nonce:, identity_token:, ip:, user_agent: nil)
        checked = verified(client_id: client_id, challenge_id: challenge_id, nonce: nonce, identity_token: identity_token,
          ip: ip, purpose: ExternalIdentities::NATIVE)
        return checked unless checked.success?
        @external.native_sign_in(evidence: checked.credential, client_id: client_id, ip_address: hint(ip, 128), user_agent: hint(user_agent, 512))
      end

      def enroll(client_id:, challenge_id:, nonce:, identity_token:, ip:, identifier:, profile: {})
        return failure(:disabled) unless @accounts
        checked = verified(client_id: client_id, challenge_id: challenge_id, nonce: nonce, identity_token: identity_token,
          ip: ip, purpose: ExternalIdentities::NATIVE_ENROLL)
        return checked unless checked.success?
        @accounts.call.register_external(identifier: identifier, evidence: checked.credential, profile: profile)
      end

      private

      def verified(client_id:, challenge_id:, nonce:, identity_token:, ip:, purpose:)
        admitted = @intake.anonymous(ip: ip, action: :native_exchange)
        return failure(admitted) if admitted.is_a?(Symbol)
        provider = @providers[client_id]
        return failure unless @profile&.client?(client_id) && provider && identity_token.is_a?(String) &&
          identity_token.ascii_only? && identity_token.bytesize.between?(1, 16_384)
        pending = @external.pending(transaction: challenge_id, browser_secret: nonce, binding_context: context(client_id))
        return failure unless pending && pending.purpose == purpose && pending.configuration.equal?(provider)
        result = @verify.call(identity_token: identity_token, pending: pending, nonce: nonce)
        evidence = provider.verify(server_result: result, transaction: pending)
        return failure unless evidence
        Result.success(user: nil, strategy: :external_identity, credential: evidence)
      end

      def context(client_id) = "native:#{client_id}"

      def failure(reason = :invalid_credentials) = Result.failure(reason: reason)

      def hint(value, limit)
        value if value.is_a?(String) && value.valid_encoding? && value.bytesize <= limit && !value.match?(/[\x00-\x1f\x7f]/)
      end
    end
  end
end
