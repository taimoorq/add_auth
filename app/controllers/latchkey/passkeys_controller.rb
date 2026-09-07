# frozen_string_literal: true

module Latchkey
  class PasskeysController < ::ApplicationController
    include Rails::AuthenticationPages

    helper Latchkey::SignInsHelper
    skip_before_action :require_authentication, raise: false
    before_action :private_response
    before_action :enabled_feature
    before_action :require_authentication, only: %i[index registration_options register rename remove change_policy reauthentication_options reauthenticate]
    protect_from_forgery with: :exception
    rescue_from Latchkey::Error, with: :service_unavailable

    def index
      @credentials = service.list(user: Current.user, session: Current.session)
      @strict = Rails::Runtime.access_policy.strict?(Current.user)
      page("list")
    end

    def registration_options
      return unless admitted(:passkey_enrollment)
      options(service.registration_options(user: Current.user, session: Current.session, browser_secret: browser_secret))
    end

    def register
      return unless admitted(:passkey_finish)
      result = service.register(transaction: params[:transaction], credential_response: credential_payload,
        user: Current.user, session: Current.session, browser_secret: browser_secret, nickname: params[:nickname])
      finish(result, destination: "/passkeys", grant: result.grant)
    end

    def authentication_options
      return unless admitted(:sign_in)
      options(service.authentication_options(browser_secret: browser_secret))
    end

    def authenticate
      return unless admitted(:passkey_finish)
      result = service.authenticate(transaction: params[:transaction], credential_response: credential_payload,
        browser_secret: browser_secret, replacing: latchkey_replacement_session, **latchkey_session_hints)
      finish(result, destination: result.success? ? after_authentication_url : "/", grant: result.success? ? result.credential : nil)
    end

    def reauthentication_options
      return unless admitted(:reauthenticate)
      options(service.authentication_options(browser_secret: browser_secret, user: Current.user,
        session: Current.session, purpose: params[:purpose]))
    end

    def reauthenticate
      return unless admitted(:passkey_finish)
      result = service.authenticate(transaction: params[:transaction], credential_response: credential_payload,
        browser_secret: browser_secret, session: Current.session)
      destination = result.success? ? Rails::Runtime.step_up_policy.rule_for(result.session.elevation_purpose).return_to : "/"
      finish(result, destination: destination, grant: result.success? ? result.credential : nil)
    end

    def rename
      management(service.rename(user: Current.user, session: Current.session, id: params[:id], nickname: params[:nickname]))
    end

    def remove
      management(service.remove(user: Current.user, session: Current.session, id: params[:id]))
    end

    def change_policy
      result = service.change_policy(user: Current.user, session: Current.session,
        strict: {"strict" => true, "default" => false}[params[:policy]], acknowledged: params[:acknowledged] == "1")
      latchkey_accept(result.credential) if result.success?
      management(result, purpose: :manage_policy)
    end

    def cancel
      service.cancel(transaction: params[:transaction], browser_secret: session[:latchkey_browser])
      head :no_content
    end

    private

    def service = Rails::Runtime.passkeys
    def browser_secret = session[:latchkey_browser] ||= Rails::Runtime.browser_binding.generate

    def enabled_feature
      head :not_found unless Rails::Runtime.config.passkeys.enabled
    end

    def authentication_partial(partial) = "latchkey/passkeys/#{partial}"

    def credential_payload
      value = params[:credential]
      value.to_unsafe_h if value.is_a?(ActionController::Parameters)
    end

    def admitted(action)
      result = Rails::Runtime.intake.anonymous(ip: request.remote_ip, action: action, challenge_token: challenge_token)
      return true if result == true
      render json: {error: "Verification could not start. Try again shortly."}, status: if result == :rate_limited
                                                                                          429
                                                                                        else
                                                                                          (result == :challenge_unavailable) ? 503 : 422
                                                                                        end
      false
    end

    def options(result)
      return render(json: result.credential) if result.success?
      error(result)
    end

    def finish(result, destination:, grant:)
      return error(result) unless result.success?
      latchkey_accept(grant) if grant
      render json: {redirect: Core::Sessions.safe_return(destination) || "/"}
    end

    def error(result)
      payload = {error: "Verification did not complete. Try another passkey or an allowed recovery method."}
      if result.reason == :elevation_required && %w[registration_options register].include?(action_name)
        payload[:redirect] = "/reauthenticate?purpose=manage_passkeys"
      end
      render json: payload, status: :unprocessable_entity
    end

    def management(result, purpose: :manage_passkeys)
      if result.success?
        redirect_to "/passkeys", status: :see_other
      elsif result.reason == :elevation_required
        redirect_to "/reauthenticate?#{URI.encode_www_form(purpose: purpose)}", status: :see_other
      else
        @error = "That change could not be made. Keep a usable sign-in method and check your selection."
        @credentials = service.list(user: Current.user, session: Current.session)
        @strict = Rails::Runtime.access_policy.strict?(Current.user)
        page("list", status: :unprocessable_entity)
      end
    end

    def service_unavailable
      render json: {error: "Passkeys are temporarily unavailable. Try again shortly."}, status: :service_unavailable
    end
  end
end
