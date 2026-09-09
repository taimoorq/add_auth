# frozen_string_literal: true

module AddAuth
  # This transport never reads/writes browser cookies or invokes the host's
  # browser Authentication concern. Hosts may map the same Core result to a
  # versioned application DTO through Runtime.mobile_authentication.
  class MobileSessionsController < ActionController::API
    before_action :private_response
    before_action :require_mobile_feature
    before_action :require_native_feature, only: %i[apple_challenge apple apple_enroll]
    before_action :require_mobile_session, except: %i[create exchange apple_challenge apple apple_enroll]
    rescue_from AddAuth::Error, ActiveRecord::ActiveRecordError, with: :unavailable

    def create
      result = Rails::Runtime.mobile_authentication.password(identifier: params[:email_address], password: params[:password],
        client_id: params[:client_id], ip: request.remote_ip, user_agent: request.user_agent, challenge_token: params[:challenge_token])
      return failure(result.reason) unless result.success?
      created(result)
    end

    def show
      render json: {session_id: @mobile_session.id, user_id: @mobile_session.user_id, expires_at: @mobile_session.expires_at}
    end

    def exchange
      admitted = Rails::Runtime.intake.anonymous(ip: request.remote_ip, action: :mobile_handoff)
      return failure(admitted) if admitted.is_a?(Symbol)
      result = Rails::Runtime.mobile_handoffs.exchange(code: params[:code], state: params[:state],
        code_verifier: params[:code_verifier], client_id: params[:client_id], ip: request.remote_ip, user_agent: request.user_agent)
      return failure(result.reason) unless result.success?
      created(result)
    end

    def apple_challenge
      result = Rails::Runtime.native_apple.start(client_id: params[:client_id], ip: request.remote_ip, challenge_token: params[:challenge_token],
        intent: params.fetch(:intent, "sign_in"))
      return failure(result.reason) unless result.success?
      challenge = result.credential
      render json: {challenge_id: challenge.id, nonce: challenge.nonce, expires_at: challenge.expires_at}, status: :created
    end

    def apple
      result = Rails::Runtime.native_apple.complete(client_id: params[:client_id], challenge_id: params[:challenge_id], nonce: params[:nonce],
        identity_token: params[:identity_token], ip: request.remote_ip, user_agent: request.user_agent)
      return failure(result.reason) unless result.success?
      created(result)
    end

    def apple_enroll
      result = Rails::Runtime.native_apple.enroll(client_id: params[:client_id], challenge_id: params[:challenge_id], nonce: params[:nonce],
        identity_token: params[:identity_token], ip: request.remote_ip, identifier: params[:email_address])
      return failure(result.reason) unless result.success?
      render json: {status: "confirmation_required"}, status: :accepted
    end

    def index
      page = Rails::Runtime.sessions.list_page(user: @mobile_user, current_session_id: @mobile_session.id, before: params[:before])
      render json: {sessions: page.entries.map { |entry|
        {id: entry.id, current: entry.current, transport: entry.transport, client_id: entry.client_id,
         authenticated_with: entry.authenticated_with, last_seen_at: entry.last_seen_at, expires_at: entry.expires_at}
      }, next_cursor: page.next_cursor}
    end

    def destroy
      Rails::Runtime.sessions.revoke(session: @mobile_session)
      head :no_content
    end

    def revoke
      revoked = Rails::Runtime.sessions.revoke_one(user: @mobile_user, session: @mobile_session, session_id: params[:id])
      head(revoked ? :no_content : :not_found)
    end

    def revoke_all
      result = Rails::Runtime.revoke_all(user: @mobile_user, session: @mobile_session,
        password: params[:password], ip: request.remote_ip, challenge_token: params[:challenge_token])
      result.success? ? head(:no_content) : failure(result.reason)
    end

    private

    def created(result)
      render json: {token: result.grant.bearer, token_type: "Bearer", expires_at: result.session.expires_at,
                    session_id: result.session.id, user_id: result.user.id}, status: :created
    end

    def require_mobile_session
      require "add_auth/core/mobile_authentication"
      bearer = Core::MobileAuthentication.bearer(request.authorization)
      grant = Rails::Runtime.sessions.resume_mobile(bearer: bearer)
      return failure(:invalid_credentials) unless grant
      @mobile_session = grant.session
      @mobile_user = grant.session.user
    end

    def require_mobile_feature
      head :not_found unless Rails::Runtime.config.mobile.enabled
    end

    def require_native_feature
      return unavailable unless Rails::Runtime.config.mobile.apple_providers.is_a?(Hash)
      head :not_found if Rails::Runtime.config.mobile.apple_providers.empty?
    end

    def private_response
      response.set_header("Cache-Control", "no-store")
      response.set_header("Referrer-Policy", "no-referrer")
      head :upgrade_required if ::Rails.env.production? && !request.ssl?
    end

    def failure(reason)
      status = Core::MobileResponse.status(reason)
      response.set_header("Retry-After", "300") if [429, 503].include?(status)
      response.set_header("WWW-Authenticate", "Bearer") if status == 401
      render json: {error: reason}, status: status
    end

    def unavailable = failure(:challenge_unavailable)
  end
end
