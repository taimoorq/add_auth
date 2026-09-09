# frozen_string_literal: true

module AddAuth
  module Rails
    module AccountPasswordEntry
      extend ActiveSupport::Concern

      included do
        protect_from_forgery with: :exception
        prepend_before_action :add_auth_account_password_entry, only: %i[new create edit update]
      end

      private

      def add_auth_account_password_entry
        return unless AddAuth.configuration.lifecycle.enabled
        verify_authenticity_token unless request.get? || request.head?
        response.set_header("Cache-Control", "no-store")
        response.set_header("Referrer-Policy", "no-referrer")
        redirect_to "/account/requests/reset_password", status: request.get? ? :found : :see_other
      end
    end
  end
end
