# frozen_string_literal: true

module Latchkey
  class ReauthenticationsController < ::ApplicationController
    include Rails::AuthenticationPages

    helper Latchkey::SignInsHelper
    skip_before_action :require_authentication, raise: false
    before_action :private_response
    before_action :enabled_feature
    before_action :require_authentication, except: %i[link confirm]
    before_action :load_purpose, only: %i[new password request_link check_email]
    protect_from_forgery with: :exception
    rescue_from Latchkey::Error, "ActiveJob::EnqueueError", with: :service_unavailable

    def new = page("form")

    def password
      result = Rails::Runtime.elevate_password(user: Current.user, session: Current.session,
        purpose: @purpose, password: params[:password], ip: request.remote_ip, challenge_token: challenge_token)
      finish(result)
    end

    def request_link
      admitted = Rails::Runtime.intake.call(identifier: Current.user.email_address, ip: request.remote_ip,
        action: :reauthenticate, challenge_token: challenge_token)
      return intake_failure(admitted) if %i[challenge_rejected challenge_unavailable].include?(admitted)
      unless admitted.is_a?(Symbol)
        session[:latchkey_browser] ||= Rails::Runtime.browser_binding.generate
        Rails::Runtime.enqueue_reauthentication(user: Current.user, session: Current.session,
          purpose: @purpose, browser_secret: session[:latchkey_browser])
      end
      redirect_to "/reauthenticate/check-email?#{URI.encode_www_form(purpose: @purpose)}", status: :see_other
    end

    def check_email = page("check_email")

    def link
      @preview = service.preview(token: params[:token], browser_secret: session[:latchkey_browser])
      page(service.confirmation_page(@preview))
    end

    def confirm
      result = service.reauthenticate(token: params[:token], session: latchkey_replacement_session,
        browser_secret: session[:latchkey_browser])
      finish(result, failure_page: "invalid_link")
    end

    private

    def service = Rails::Runtime.email(purpose: :reauthentication)

    def enabled_feature
      head :not_found unless Rails::Runtime.config.step_up.enabled
    end

    def load_purpose
      @rule = Rails::Runtime.step_up_policy.reauthentication_rule_for(params[:purpose])
      return head :not_found unless @rule
      @purpose = params[:purpose].to_s
      @methods = Rails::Runtime.step_up_policy.methods_for(user: Current.user, purpose: @purpose)
    end

    def finish(result, failure_page: "form")
      if result.success?
        destination = Rails::Runtime.step_up_policy.rule_for(result.session.elevation_purpose).return_to
        latchkey_accept(result.credential)
        redirect_to destination, status: :see_other
      else
        @error = "We could not verify this request. Try again from the browser where you started."
        if %i[rate_limited challenge_rejected challenge_unavailable].include?(result.reason)
          intake_failure(result.reason)
        else
          page(failure_page, status: :unprocessable_entity)
        end
      end
    end

    def authentication_partial(partial) = "latchkey/reauthentications/#{partial}"
  end
end
