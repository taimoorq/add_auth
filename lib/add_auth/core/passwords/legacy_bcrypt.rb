# frozen_string_literal: true

require "bcrypt"
require "add_auth/core/passwords/bcrypt_support"

module AddAuth
  module Core
    module Passwords
      # Verification only. New password assignment remains the Rails host's job.
      # The source profile chooses this adapter explicitly; no digest guessing.
      class LegacyBcrypt
        PATTERN = BcryptSupport::PATTERN

        def initialize(pepper: -> {}, maximum_cost: 14)
          raise ArgumentError, "pepper must be callable" unless pepper.respond_to?(:call)
          raise ArgumentError, "maximum_cost must be between 4 and 20" unless maximum_cost.is_a?(Integer) && maximum_cost.between?(4, 20)
          @pepper, @maximum_cost = pepper, maximum_cost
          @support = BcryptSupport.new(maximum_cost: maximum_cost)
        end

        def available?(digest:)
          @support.available?(digest: digest) && valid_pepper?(@pepper.call)
        end

        def verify(digest:, password:)
          return false unless password.is_a?(String) && password.valid_encoding? && password.bytesize.between?(1, 1024)
          return false unless @support.available?(digest: digest)
          pepper = @pepper.call
          return false unless valid_pepper?(pepper)
          BCrypt::Password.new(digest).is_password?((pepper.nil? || pepper.empty?) ? password : "#{password}#{pepper}")
        rescue BCrypt::Errors::InvalidHash, BCrypt::Errors::InvalidSecret, ArgumentError, EncodingError
          false
        end

        def inspect = "#<AddAuth::Core::Passwords::LegacyBcrypt [FILTERED]>"

        private

        def valid_pepper?(pepper) = pepper.nil? || (pepper.is_a?(String) && pepper.valid_encoding? && pepper.bytesize <= 1024)
      end
    end
  end
end
