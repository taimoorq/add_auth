# frozen_string_literal: true

module AddAuth
  module Rails
    module AuthenticationPages
      def add_auth_password_sign_in
        return head :not_found unless Runtime.config.passwords_enabled
        intake = Runtime.intake.call(identifier: params[:email_address], ip: request.remote_ip,
          action: :sign_in, challenge_token: challenge_token)
        return intake_failure(intake) if intake.is_a?(Symbol)
        grant = Runtime.sessions.authenticate(identifier: intake, password: params[:password], replacing: add_auth_replacement_session, **add_auth_session_hints) do
          Runtime.authenticate_password(identifier: intake, password: params[:password])
        end
        if grant
          destination = after_authentication_url
          add_auth_accept(grant)
          redirect_to destination, status: :see_other
        else
          @error = "Email or password is incorrect. Try again or request a sign-in link."
          page("form", status: :unprocessable_entity)
        end
      end

      private

      def valid_request_origin?
        Core::Intake.origin_allowed?(origin: request.origin, base_url: request.base_url)
      end

      def challenge_token
        params[:challenge_token].presence || params["cf-turnstile-response"].presence || params["g-recaptcha-response"].presence
      end

      def service_unavailable
        @error = "Sign-in is temporarily unavailable. Please try again shortly."
        response.set_header("Retry-After", "60")
        page("form", status: :service_unavailable)
      end

      def private_response
        response.set_header("Cache-Control", "no-store")
        response.set_header("Referrer-Policy", "no-referrer")
      end

      def page(partial, status: :ok)
        @page_partial = authentication_partial(partial)
        respond_to do |format|
          format.html { render "add_auth/sign_ins/show", layout: "add_auth/authentication", status: status }
          format.turbo_stream { render turbo_stream: turbo_stream.update("add_auth-content", partial: @page_partial), status: status }
        end
      end

      def authentication_partial(partial) = "add_auth/sign_ins/#{partial}"

      def intake_failure(reason)
        @error, status = {
          rate_limited: ["Too many attempts. Try again in five minutes.", :too_many_requests],
          challenge_unavailable: ["Verification is temporarily unavailable. Please try again shortly.", :service_unavailable],
          challenge_rejected: ["Verification failed. Please try again.", :unprocessable_entity]
        }.fetch(reason, ["Check your credentials and try again.", :unprocessable_entity])
        response.set_header("Retry-After", "300") if %i[too_many_requests service_unavailable].include?(status)
        page("form", status: status)
      end
    end
  end
end
