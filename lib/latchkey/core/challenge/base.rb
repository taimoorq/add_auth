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
      # Concrete adapters (Turnstile, reCAPTCHA) use only Ruby's standard
      # library and are loaded with Core. A host opts in with
      # `bin/rails g latchkey:challenge turnstile`, which generates the
      # initializer stanza and route; no provider call happens until the host
      # supplies keys and includes the action in `challenge_on`.
      class Base
        Verification = Data.define(:status, :reason) do
          def initialize(status:, reason: nil)
            unless %i[success rejected unavailable].include?(status)
              raise ArgumentError, "unknown challenge status"
            end
            super
          end

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

        def inspect = "#<#{self.class} [FILTERED]>"
        attr_reader :allowed_hostnames

        private

        def require_value(value, name, max_bytes:)
          unless value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, max_bytes)
            raise ArgumentError, "challenge #{name} must be present"
          end
          value.dup.freeze
        end

        def normalize_hostnames(hostnames)
          values = hostnames.is_a?(String) ? hostnames.split(",") : Array(hostnames)
          values.map { |hostname| hostname.to_s.strip.downcase }.reject(&:empty?).uniq.freeze
        end

        def normalize_action(action)
          value = action.to_s
          raise ArgumentError, "challenge action must be present" unless value.match?(/\A[a-zA-Z0-9._:-]{1,64}\z/)
          value
        end

        def hostname_allowed?(hostname)
          hostname.is_a?(String) && !hostname.empty? &&
            (@allowed_hostnames.empty? || @allowed_hostnames.include?(hostname.downcase))
        end

        def response_failure(payload)
          return unavailable(:verification_service) unless [true, false].include?(payload["success"])
          return if payload["success"] == true
          errors = payload["error-codes"]
          valid_errors = errors.nil? || (errors.is_a?(Array) && errors.all? { |value| value.is_a?(String) })
          return unavailable(:verification_service) unless valid_errors
          service_errors = %w[internal-error missing-input-secret invalid-input-secret bad-request]
          return unavailable(:verification_service) if (Array(errors) & service_errors).any?
          rejected(:challenge_rejected)
        end

        def success = Verification.new(status: :success)
        def rejected(reason) = Verification.new(status: :rejected, reason:)
        def unavailable(reason) = Verification.new(status: :unavailable, reason:)
      end
    end
  end
end
