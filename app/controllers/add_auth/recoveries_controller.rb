# frozen_string_literal: true

module AddAuth
  class RecoveriesController < ::ApplicationController
    include Rails::AuthenticationPages

    helper AddAuth::SignInsHelper
    skip_before_action :require_authentication, raise: false
    before_action :private_response
    before_action :enabled_feature
    protect_from_forgery with: :exception
    rescue_from AddAuth::Error, "ActiveJob::EnqueueError", with: :service_unavailable

    def new = page("form")
    def check_email = page("check_email")

    def request_link
      value = Rails::Runtime.intake.call(identifier: params[:email_address], ip: request.remote_ip,
        action: :email_link, challenge_token: challenge_token)
      return intake_failure(value) if %i[challenge_rejected challenge_unavailable].include?(value)
      Rails::Runtime.enqueue_recovery(value) unless value.is_a?(Symbol)
      redirect_to "/recover/check-email", status: :see_other
    end

    def link
      @preview = service.preview(token: params[:token])
      page(service.confirmation_page(@preview))
    end

    def confirm
      result = service.consume(token: params[:token], current_session: add_auth_replacement_session,
        switch_account: params[:switch_account] == "1")
      if result.success?
        add_auth_accept(result.grant)
        redirect_to "/passkeys", status: :see_other
      else
        page("invalid_link", status: :unprocessable_entity)
      end
    end

    private

    def service = Rails::Runtime.email(purpose: :recovery)
    def authentication_partial(partial) = "add_auth/recoveries/#{partial}"

    def enabled_feature
      head :not_found unless Rails::Runtime.config.passkeys.enabled
    end
  end
end
