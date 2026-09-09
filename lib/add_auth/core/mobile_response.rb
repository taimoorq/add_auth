# frozen_string_literal: true

module AddAuth
  module Core
    module MobileResponse
      def self.status(reason)
        {rate_limited: 429, challenge_unavailable: 503, challenge_rejected: 422, unconfirmed: 403, locked: 423, disabled: 403,
         elevation_required: 403}.fetch(reason, 401)
      end
    end
  end
end
