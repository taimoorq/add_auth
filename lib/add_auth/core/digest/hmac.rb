# frozen_string_literal: true

require "openssl"

module AddAuth
  module Core
    module Digest
      # Rails derives the base secret; Core only receives key material.
      # Purpose separation remains identical for injected and Rails-derived keys.
      class Hmac < Base
        KEY_LENGTH = 32

        def initialize(salt:, secret:)
          unless salt.is_a?(String) && !salt.strip.empty?
            raise ArgumentError, "salt must be a nonblank string"
          end
          unless secret.is_a?(String) && secret.bytesize >= KEY_LENGTH
            raise ArgumentError, "secret must contain at least 32 bytes of key material"
          end
          @key = OpenSSL::HMAC.digest("SHA256", secret, salt).freeze
        end

        def digest(token)
          unless token.is_a?(String) && !token.empty?
            raise ArgumentError, "token must be a nonempty string"
          end
          OpenSSL::HMAC.hexdigest("SHA256", @key, token)
        end

        def matches?(digest, token)
          return false unless digest.is_a?(String) && digest.bytesize == 64
          return false unless token.is_a?(String) && !token.empty?

          OpenSSL.fixed_length_secure_compare(digest, self.digest(token))
        end

        def inspect = "#<#{self.class} [FILTERED]>"
      end
    end
  end
end
