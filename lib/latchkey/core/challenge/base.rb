# frozen_string_literal: true

module Latchkey
  module Core
    module Challenge
      # The adapter contract every challenge provider implements. See
      # docs/authentication-gem-plan.md section 9 for the full design,
      # including the decision that matters most here: #verify returns a
      # result with a real `unavailable?` state, distinct from `rejected?`.
      # A provider outage and a failed human challenge are different events
      # and most integrations in the wild conflate them -- either locking out
      # every user during an outage, or waving everyone through. The host
      # chooses which way to fail via `Configuration#challenge_when_unavailable`.
      #
      # Concrete adapters (Turnstile, reCAPTCHA) are intentionally not
      # required by default from lib/latchkey.rb -- only Null and Test are.
      # A host opts in with `bin/rails g latchkey:challenge turnstile`, which
      # both generates the initializer stanza and requires the file.
      class Base
        Verification = Struct.new(:status, :reason, keyword_init: true) do
          def success? = status == :success
          def rejected? = status == :rejected
          def unavailable? = status == :unavailable
        end

        def site_key
          raise NotImplementedError, "#{self.class} must implement #site_key"
        end

        def script_url
          raise NotImplementedError, "#{self.class} must implement #script_url"
        end

        def stimulus_controller
          raise NotImplementedError, "#{self.class} must implement #stimulus_controller"
        end

        # @param token [String, nil] the provider's response token from the form.
        # @param remote_ip [String, nil]
        # @param action [Symbol] one of Configuration#challenge_on's entries;
        #   used to bind the token to the form it was minted for.
        # @return [Verification]
        def verify(token:, remote_ip:, action:)
          raise NotImplementedError, "#{self.class} must implement #verify"
        end

        private

        def success = Verification.new(status: :success)
        def rejected(reason) = Verification.new(status: :rejected, reason:)
        def unavailable(reason) = Verification.new(status: :unavailable, reason:)
      end
    end
  end
end
