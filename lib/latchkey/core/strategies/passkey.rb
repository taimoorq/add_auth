# frozen_string_literal: true

module Latchkey
  module Core
    module Strategies
      # WebAuthn passkeys: registration, discoverable sign-in, and
      # conditional UI (autofill). See docs/authentication-gem-plan.md
      # section 6 for the three flows and the decisions that aren't obvious
      # from the WebAuthn spec alone:
      #
      #   - sign_count of 0 is accepted unconditionally; only a *decreasing*
      #     non-zero counter is treated as clone evidence. Apple/Google
      #     platform authenticators always report 0.
      #   - `webauthn_id` (the user handle) must be an opaque random value,
      #     never the primary key or the email -- it is enumerable by anyone
      #     with the physical device.
      #   - built on cedarcode/webauthn for attestation/CBOR/COSE; a
      #     `WebAuthn::RelyingParty` is instantiated per Latchkey
      #     configuration rather than the library's process-global config, so
      #     multi-tenant/multi-domain hosts are possible from day one.
      #
      # TODO(v1): implement against the `webauthn` gem once the
      # `latchkey_credentials` table (section 3) exists.
      module Passkey
        module_function

        # @return [Hash] WebAuthn::PublicKeyCredentialCreationOptions for
        #   navigator.credentials.create(), plus the challenge to stash in
        #   the session.
        def registration_options(user:)
          raise NotImplementedError, "Latchkey::Core::Strategies::Passkey.registration_options is not implemented yet"
        end

        # @return [Latchkey::Result] on success, credential is the newly
        #   stored Latchkey::Credential-equivalent record.
        def register(user:, credential_response:, challenge:)
          raise NotImplementedError, "Latchkey::Core::Strategies::Passkey.register is not implemented yet"
        end

        # @return [Hash] WebAuthn::PublicKeyCredentialRequestOptions with an
        #   empty allowCredentials -- discoverable/conditional-UI sign-in
        #   does not take an identifier up front.
        def authentication_options
          raise NotImplementedError, "Latchkey::Core::Strategies::Passkey.authentication_options is not implemented yet"
        end

        # @return [Latchkey::Result] resolves the user from the assertion's
        #   userHandle; verifies the signature and the sign counter.
        def authenticate(credential_response:, challenge:)
          raise NotImplementedError, "Latchkey::Core::Strategies::Passkey.authenticate is not implemented yet"
        end
      end
    end
  end
end
