# frozen_string_literal: true

module Latchkey
  module Core
    module Strategies
      # Passwordless sign-in by email. See
      # docs/authentication-gem-plan.md section 5 for the full flow and the
      # two hazards that drive its defaults:
      #
      #   - link prewarming: the emailed link is a GET that only *renders* a
      #     confirmation; a POST from that page is what actually consumes the
      #     token. Consuming on GET is exactly what breaks under Outlook
      #     SafeLinks, Slack/Teams unfurlers, and mail security proxies that
      #     prefetch every link in a message.
      #   - enumeration: #issue must always look like it succeeded, whether
      #     or not the identifier matches a user, and independent of the two
      #     rate limits (IP and hashed-identifier) it should be checked
      #     against upstream in the host's controller.
      #
      # TODO(v1): implement against Latchkey::Core token minting (a
      # `latchkey_sign_in_tokens` row per the schema in section 3 -- single-use
      # and revocable, which is why this is a stored digest and not a
      # `generates_token_for` token) once that table exists.
      module EmailLink
        module_function

        # @param identifier [String] the raw, unnormalized value from the form.
        # @return [void] always -- see enumeration-safety note above. The
        #   controller's response must not depend on this method's internal
        #   branching.
        def issue(identifier:)
          raise NotImplementedError, "Latchkey::Core::Strategies::EmailLink.issue is not implemented yet"
        end

        # @param token [String] the raw (non-digested) token from the URL/form.
        # @return [Latchkey::Result]
        def consume(token:)
          raise NotImplementedError, "Latchkey::Core::Strategies::EmailLink.consume is not implemented yet"
        end
      end
    end
  end
end
