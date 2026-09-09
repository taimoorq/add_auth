# frozen_string_literal: true

require "bcrypt"

module AddAuth
  module Core
    module Passwords
      # Explicit metadata support for the stock Rails bcrypt verifier, not an
      # algorithm detector or authentication proof. Override verifiers supply
      # their own available?(digest:) contract instead of using this adapter.
      class BcryptSupport
        PATTERN = /\A\$2[aby]\$(\d{2})\$[.\/A-Za-z0-9]{53}\z/

        def initialize(maximum_cost: BCrypt::Engine::MAX_COST)
          @maximum_cost = maximum_cost
        end

        def available?(digest:)
          return false unless digest.is_a?(String) && digest.valid_encoding? && digest.bytesize == 60
          match = PATTERN.match(digest)
          !!(match && match[1].to_i.between?(BCrypt::Engine::MIN_COST, @maximum_cost))
        rescue ArgumentError, EncodingError
          false
        end
      end
    end
  end
end
