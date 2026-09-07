# frozen_string_literal: true

module Latchkey
  class SessionsController < ::ApplicationController
    include Rails::AuthenticationPages

    rescue_from Latchkey::Error, with: :service_unavailable
    helper Latchkey::SignInsHelper
    before_action :require_authentication
    before_action :private_response
    protect_from_forgery with: :exception
    layout "application"

    def index
      @sessions = Rails::Runtime.sessions.list(user: Current.user, current_session_id: Current.session.id)
      respond_to do |format|
        format.html { render "latchkey/sessions/index" }
        format.turbo_stream do
          render turbo_stream: turbo_stream.update("latchkey-session-content", partial: "latchkey/sessions/list")
        end
      end
    end

    def destroy
      target_id = params[:id].to_s
      if target_id.match?(/\A[1-9]\d*\z/) && target_id.to_i == Current.session.id
        terminate_session
        return redirect_to Rails::Runtime.sign_in_path, status: :see_other
      end

      revoked = Rails::Runtime.sessions.revoke_one(user: Current.user, session: Current.session, session_id: target_id)
      return head :not_found unless revoked

      redirect_to security_sessions_path, status: :see_other
    end

    def new_revoke_all
      @elevated = Rails::Runtime.sessions.with_elevation(user: Current.user, session: Current.session,
        purpose: :sign_out_everywhere, policy: Rails::Runtime.step_up_policy).success?
      @password_available = Rails::Runtime.access_policy.methods_for(Current.user).include?(:password)
      page("revoke_all")
    end

    def revoke_all
      authorization = Rails::Runtime.revoke_all(user: Current.user, session: Current.session,
        password: params[:password], ip: request.remote_ip, challenge_token: challenge_token)
      return intake_failure(authorization.reason) unless authorization.success?

      terminate_session
      redirect_to Rails::Runtime.sign_in_path, status: :see_other
    end

    private

    def authentication_partial(_partial)
      @password_available = Rails::Runtime.access_policy.methods_for(Current.user).include?(:password)
      "latchkey/sessions/revoke_all"
    end
  end
end
