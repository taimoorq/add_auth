# frozen_string_literal: true

require "latchkey/rails/runtime"

module Latchkey
  module Rails
    module Elevation
      extend ActiveSupport::Concern

      class_methods do
        # A navigation guard, not mutation authorization. Use the block helper
        # below for writes, alongside the host's resource authorization.
        def require_elevated_session(purpose:, **options)
          before_action(**options) { latchkey_require_elevation(purpose) }
        end
      end

      private

      def with_elevated_session(purpose:, &block)
        raise ArgumentError, "a database mutation block is required" unless block
        Runtime.sessions.with_elevation(user: Current.user, session: Current.session,
          purpose: purpose, policy: Runtime.step_up_policy, &block)
      end

      def latchkey_require_elevation(purpose)
        return require_authentication unless authenticated?
        result = Runtime.sessions.with_elevation(user: Current.user, session: Current.session,
          purpose: purpose, policy: Runtime.step_up_policy)
        return if result.success?
        redirect_to "/reauthenticate?#{URI.encode_www_form(purpose: purpose)}", status: request.get? ? :found : :see_other
      end
    end
  end
end
