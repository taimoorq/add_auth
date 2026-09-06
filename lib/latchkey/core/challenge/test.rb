# frozen_string_literal: true

module Latchkey
  module Core
    module Challenge
      # Deterministic adapter for specs. See
      # docs/authentication-gem-plan.md section 13 -- `latchkey_challenges_pass!`,
      # `_fail!`, and `_go_down!` test helpers (not yet implemented) are
      # expected to flip this adapter's mode rather than stub HTTP calls.
      class Test < Base
        def initialize(mode: :success)
          @mode = mode
        end

        attr_accessor :mode

        def site_key = "test-site-key"
        def script_url = nil
        def stimulus_controller = "latchkey--challenge-test"

        def verify(token:, remote_ip:, action:)
          case @mode
          when :success then success
          when :rejected then rejected(:challenge_rejected)
          when :unavailable then unavailable(:verification_service)
          else
            raise ArgumentError, "unknown Test challenge mode: #{@mode.inspect}"
          end
        end
      end
    end
  end
end
