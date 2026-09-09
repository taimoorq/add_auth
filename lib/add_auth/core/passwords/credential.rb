# frozen_string_literal: true

require "bcrypt"

module AddAuth
  module Core
    module Passwords
      class Credential
        def self.scheme_after_assignment(scheme:, password:, digest_changed:)
          (digest_changed && password.is_a?(String) && !password.empty?) ? "rails" : scheme
        end

        def initialize(legacy_verifier:)
          @legacy = legacy_verifier
        end

        def authenticate(user:, password:, current:)
          return Result.failure(reason: :invalid_credentials) unless password.is_a?(String) && password.valid_encoding? && password.bytesize.between?(1, 1024)
          verified = case scheme(user)
          when nil, "rails" then current.call(password)
          when "devise_bcrypt" then @legacy&.verify(digest: user.password_digest, password: password) == true
          else false
          end
          verified ? Result.success(user: user, strategy: :password) : Result.failure(reason: :invalid_credentials)
        rescue BCrypt::Errors::InvalidHash, BCrypt::Errors::InvalidSecret, ArgumentError, EncodingError
          Result.failure(reason: :invalid_credentials)
        end

        # Availability is not authentication. It asks the explicitly selected
        # verifier whether it supports this persisted credential with its current
        # configuration. Older/custom adapters without that contract fail closed.
        def available?(user:, current:)
          return false unless user.respond_to?(:password_digest)
          digest = user.password_digest
          return false unless digest.is_a?(String) && digest.valid_encoding? && !digest.empty?
          verifier = case scheme(user)
          when nil, "rails" then current
          when "devise_bcrypt" then @legacy
          end
          verifier.respond_to?(:available?) && verifier.available?(digest: digest) == true
        end

        private

        def scheme(user) = user.respond_to?(:add_auth_password_scheme) ? user.add_auth_password_scheme : nil
      end
    end
  end
end
