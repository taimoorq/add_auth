# frozen_string_literal: true

module AddAuth
  module Core
    module Digest
      # The adapter contract every token/session digest implementation
      # satisfies. See docs/authentication-gem-plan.md section 2's
      # "Pluggable cryptography" subsection: unlike the Challenge adapter,
      # there is no credible reason to swap this for a *security* property --
      # the reason to override it is organizational (a host mandated to run
      # OpenSSL in FIPS mode, or to route HMAC operations through an HSM).
      # Any object responding to #digest and #matches? satisfies this
      # contract; Base exists to document it and to fail loudly if a
      # concrete adapter forgets a method, the same role Challenge::Base
      # plays for challenge providers.
      class Base
        # @param token [String] the raw, high-entropy secret (a session
        #   token, a sign-in token) as presented by the client.
        # @return [String] an opaque digest safe to store at rest.
        def digest(token)
          raise NotImplementedError, "#{self.class} must implement #digest"
        end

        # @param digest [String, nil] the stored digest to compare against.
        # @param token [String, nil] the raw token presented by the client.
        # @return [Boolean] true only for a byte-exact match of the digest
        #   the same token would produce, compared in constant time.
        def matches?(digest, token)
          raise NotImplementedError, "#{self.class} must implement #matches?"
        end
      end
    end
  end
end
