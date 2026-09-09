# frozen_string_literal: true

module AddAuth
  class AccountsController < ::ApplicationController
    include Rails::AuthenticationPages

    skip_before_action :require_authentication, raise: false
    layout "add_auth/authentication"
    helper AddAuth::SignInsHelper
    before_action :require_feature
    before_action :private_response
    before_action :require_add_auth_authentication, only: %i[edit_email change_email edit_password change_password confirm_deletion destroy]
    protect_from_forgery with: :exception
    rescue_from AddAuth::Error, "ActiveJob::EnqueueError", with: :service_unavailable

    def new = page("register")
    def check_email = page("check_email")

    def create
      admitted = intake(:register)
      return intake_failure(admitted) if admitted.is_a?(Symbol)
      result = Rails::Runtime.accounts.register(identifier: admitted, password: params[:password], profile: registration_profile)
      if result.success?
        redirect_to "/account/check-email", status: :see_other
      else
        @error = "Check your email and choose a password that meets this application's requirements."
        page("register", status: :unprocessable_entity)
      end
    end

    def request_form
      @purpose = purpose
      page("request")
    end

    def request_proof
      @purpose = purpose
      admitted = intake(:account_request)
      return intake_failure(admitted) if %i[challenge_rejected challenge_unavailable].include?(admitted)
      Rails::Runtime.enqueue_account_request(identifier: admitted, purpose: @purpose) unless admitted.is_a?(Symbol)
      redirect_to "/account/check-email", status: :see_other
    end

    def proof
      @purpose = purpose
      result = Rails::Runtime.accounts.preview(token: params[:token], purpose: @purpose)
      page(result.success? ? "proof" : "invalid_proof")
    end

    def consume
      @purpose = purpose
      admitted = Rails::Runtime.intake.anonymous(ip: request.remote_ip, action: :account_consume)
      return intake_failure(admitted) if admitted.is_a?(Symbol)
      result = Rails::Runtime.accounts.consume(token: params[:token], purpose: @purpose, password: params[:password])
      if result.success?
        redirect_to "/sign-in", status: :see_other, notice: "Your account has been updated. Sign in to start a new session."
      else
        @error = "This request could not be completed. Check the password requirements or request a new link."
        page("proof", status: :unprocessable_entity)
      end
    end

    def edit_email = page("email")
    def edit_password = page("password")
    def confirm_deletion = page("delete")

    def destroy
      result = Rails::Runtime.accounts.delete_account(user: Current.user, session: Current.session)
      if result.success?
        terminate_session
        redirect_to "/sign-in", status: :see_other, notice: "Your account was deleted."
      elsif result.reason == :elevation_required
        redirect_to "/reauthenticate?purpose=delete_account", status: :see_other
      else
        @error = "Your account could not be deleted. Contact support if this continues."
        page("delete", status: :unprocessable_entity)
      end
    end

    def change_password
      result = Rails::Runtime.accounts.change_password(user: Current.user, session: Current.session, password: params[:password])
      if result.success?
        terminate_session
        redirect_to "/sign-in", status: :see_other, notice: "Your password was changed. Sign in with your new password."
      elsif result.reason == :elevation_required
        redirect_to "/reauthenticate?purpose=change_password", status: :see_other
      else
        @error = "This password cannot be used. Check the password requirements and try again."
        page("password", status: :unprocessable_entity)
      end
    end

    def change_email
      result = Rails::Runtime.accounts.change_email(user: Current.user, session: Current.session, identifier: params[:email_address])
      if result.success?
        redirect_to "/account/check-email", status: :see_other
      elsif result.reason == :elevation_required
        redirect_to "/reauthenticate?purpose=change_email", status: :see_other
      else
        @error = "This email address cannot be used. Check it and try again."
        page("email", status: :unprocessable_entity)
      end
    end

    private

    # Host controllers may override with an explicit Rails parameter allowlist.
    # The default does not forward arbitrary account/role parameters.
    def registration_profile = {}

    def require_feature
      head :not_found unless AddAuth.configuration.lifecycle.enabled
    end

    def purpose
      Core::AccountLifecycle::PURPOSES.include?(params[:purpose]) ? params[:purpose] : "confirm"
    end

    def intake(action)
      Rails::Runtime.intake.call(identifier: params[:email_address], ip: request.remote_ip, action: action, challenge_token: challenge_token)
    end

    def authentication_partial(partial) = "add_auth/accounts/#{partial}"

    def service_unavailable
      @error = "Account requests are temporarily unavailable. Please try again shortly."
      response.set_header("Retry-After", "60")
      page("unavailable", status: :service_unavailable)
    end

    def intake_failure(reason)
      @error = "This request could not be verified. Please try again shortly."
      status = {rate_limited: :too_many_requests, challenge_unavailable: :service_unavailable}.fetch(reason, :unprocessable_entity)
      response.set_header("Retry-After", "300") if %i[too_many_requests service_unavailable].include?(status)
      page("unavailable", status: status)
    end
  end
end
