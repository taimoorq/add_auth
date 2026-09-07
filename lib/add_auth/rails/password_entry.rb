# frozen_string_literal: true

require "add_auth/rails/authentication_pages"

module AddAuth
  module Rails
    # Protects every route to the generated SessionsController#create, including
    # host aliases. Keep the host file intact, but make the shared entry point the
    # authority. Verify CSRF explicitly before rendering halts later callbacks.
    module PasswordEntry
      extend ActiveSupport::Concern
      include AuthenticationPages

      included do
        helper AddAuth::SignInsHelper
        protect_from_forgery with: :exception
        prepend_before_action :add_auth_password_entry, only: %i[new create]
        rescue_from AddAuth::Error, with: :service_unavailable
      end

      private

      def add_auth_password_entry
        if action_name == "new"
          private_response
          return page("form")
        end
        verify_authenticity_token
        private_response
        add_auth_password_sign_in
      end
    end
  end
end
