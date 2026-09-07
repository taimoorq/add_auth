# frozen_string_literal: true

module Latchkey
  class SignInsController < ::ApplicationController
    include Rails::AuthenticationPages

    skip_before_action :require_authentication, raise: false
    layout "latchkey/authentication"
    helper Latchkey::SignInsHelper
    before_action :private_response
    protect_from_forgery with: :exception
    rescue_from Latchkey::Error, "ActiveJob::EnqueueError", with: :service_unavailable

    def new
      page("form")
    end

    def password = latchkey_password_sign_in

    def request_link
      return head :not_found unless Core::Intake.email_available?(Rails::Runtime.config)
      intake = Rails::Runtime.intake.call(identifier: params[:email_address], ip: request.remote_ip,
        action: :email_link, challenge_token: challenge_token)
      return intake_failure(intake) if %i[challenge_rejected challenge_unavailable].include?(intake)
      unless intake.is_a?(Symbol)
        session[:latchkey_browser] ||= Rails::Runtime.browser_binding.generate
        Rails::Runtime.enqueue_email(intake, browser_secret: session[:latchkey_browser])
      end
      redirect_to "/sign-in/check-email", status: :see_other
    end

    def check_email
      return head :not_found unless Core::Intake.email_available?(Rails::Runtime.config)
      page("check_email")
    end

    def link
      return head :not_found unless Core::Intake.email_available?(Rails::Runtime.config)
      @preview = Rails::Runtime.email.preview(token: params[:token], browser_secret: session[:latchkey_browser])
      # GET does not resume/upgrade an existing session or consume this link.
      page(Rails::Runtime.email.confirmation_page(@preview))
    end

    def confirm
      return head :not_found unless Core::Intake.email_available?(Rails::Runtime.config)
      previous = latchkey_replacement_session
      grant = nil
      result = Rails::Runtime.email.consume(token: params[:token], current_session: previous,
        switch_account: params[:switch_account] == "1", browser_secret: session[:latchkey_browser]) do |user, persist|
        grant = Rails::Runtime.sessions.create_in_transaction(user: user, method: :email_link, persist: persist,
          replacing: previous, **latchkey_session_hints)
        grant&.session
      end
      if result.success?
        destination = after_authentication_url
        latchkey_accept(grant)
        redirect_to destination, status: :see_other
      else
        page("invalid_link", status: :unprocessable_entity)
      end
    end

    private
  end
end
