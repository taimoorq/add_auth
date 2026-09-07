# frozen_string_literal: true

module AddAuth
  module Core
    module Challenge
      # The default adapter: no challenge configured, every verification
      # succeeds, and the view helper renders nothing. This is what makes
      # `add_auth_challenge_tag` safe to leave in a generated view whether or
      # not the host has configured Turnstile/reCAPTCHA (section 9).
      class Null < Base
        def site_key = nil
        def script_url = nil
        def stimulus_controller = nil

        def verify(token:, remote_ip:, action:)
          success
        end
      end
    end
  end
end
