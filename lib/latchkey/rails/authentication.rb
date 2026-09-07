# frozen_string_literal: true

require "latchkey/rails/runtime"

module Latchkey
  module Rails
    # Included AFTER the host Authentication concern. No parallel session model.
    module Authentication
      private

      def find_session_by_cookie
        grant = Runtime.sessions.resume(signed_value: cookies.signed[:session_id])
        latchkey_write_cookie(grant) if grant&.bearer
        grant&.session
      end

      def start_new_session_for(user)
        grant = Runtime.sessions.start(user: user, method: :password, replacing: latchkey_replacement_session, **latchkey_session_hints)
        raise Latchkey::Error, "account is not eligible to sign in" unless grant
        latchkey_accept(grant)
      end

      def latchkey_session_hints
        {user_agent: request.user_agent.to_s.truncate_bytes(512), ip_address: request.remote_ip}
      end

      def latchkey_replacement_session
        Runtime.sessions.replacement_for(signed_value: cookies.signed[:session_id])
      end

      def latchkey_accept(grant)
        destination = Core::Sessions.safe_return(session[:return_to_after_authenticating])
        reset_session
        session[:return_to_after_authenticating] = destination if destination
        latchkey_write_cookie(grant)
        Current.session = grant.session
      end

      def latchkey_write_cookie(grant)
        cookies.signed[:session_id] = {value: grant.bearer, expires: grant.session.expires_at,
          httponly: true, secure: request.ssl? || ::Rails.env.production?, same_site: :lax, path: "/"}
      end

      def terminate_session
        Runtime.sessions.revoke(session: Current.session) if Current.session
        Current.reset
        reset_session
        cookies.delete(:session_id, path: "/")
      end

      def request_authentication
        session[:return_to_after_authenticating] = Core::Sessions.safe_return(request.fullpath) if request.get?
        redirect_to Runtime.sign_in_path, status: request.get? ? :found : :see_other
      end

      def after_authentication_url
        Core::Sessions.safe_return(session.delete(:return_to_after_authenticating)) || "/"
      end
    end
  end
end
