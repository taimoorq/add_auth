# frozen_string_literal: true

module AddAuth
  module Core
    class MobileAuthentication
      def initialize(sessions:, profile:, intake:, verify_password:)
        @sessions, @profile, @intake, @verify_password = sessions, profile, intake, verify_password
      end

      def password(identifier:, password:, client_id:, ip:, user_agent: nil, challenge_token: nil)
        admitted = @intake.call(identifier: identifier, ip: ip, action: :sign_in, challenge_token: challenge_token)
        return Result.failure(reason: admitted) if admitted.is_a?(Symbol)
        return Result.failure(reason: :invalid_credentials) unless @profile&.client?(client_id) && password.is_a?(String) &&
          password.valid_encoding? && password.bytesize.between?(1, 1024) && !password.include?("\0")

        @sessions.authenticate_result(identifier: admitted, password: password, transport: :mobile, client_id: client_id, disclose_policy: true,
          ip_address: hint(ip, 128), user_agent: hint(user_agent, 512)) do
          @verify_password.call(identifier: admitted, password: password)
        end
      end

      def self.bearer(header)
        return unless header.is_a?(String) && header.bytesize == 54
        match = /\ABearer (am1:[A-Za-z0-9_-]{43})\z/i.match(header)
        match[1] if match && MobileProfile::PATTERN.match?(match[1])
      end

      private

      def hint(value, limit)
        value if value.is_a?(String) && value.valid_encoding? && value.bytesize <= limit && !value.match?(/[\x00-\x1f\x7f]/)
      end
    end
  end
end
