# frozen_string_literal: true

require "add_auth/rails/provider_libraries/apple_form_post_correlation"
require "add_auth/rails/provider_libraries/omniauth"
require "add_auth/rails/provider_libraries/omniauth_correlation"
require "add_auth/rails/provider_libraries/request_protection"

module AddAuth
  # The protocol library has already verified the callback before this
  # controller sees it. This controller only starts/consumes a Core
  # transaction and maps its typed result to the normal Rails session/UI.
  class ProviderSignInsController < ::ApplicationController
    include Rails::AuthenticationPages

    skip_before_action :require_authentication, raise: false
    before_action :private_response
    before_action :load_provider
    before_action :require_add_auth_authentication, unless: :anonymous_or_callback?
    protect_from_forgery with: :exception, except: :callback
    helper AddAuth::SignInsHelper
    layout "add_auth/authentication"
    rescue_from AddAuth::Error, with: :provider_unavailable

    # This deliberately renders an ordinary confirmation form instead of
    # redirecting to /auth/:provider: OmniAuth 2 accepts a CSRF-protected POST,
    # and a 303 would turn that navigation into an unsafe GET. It is equally
    # usable with Turbo, inside a frame, and with JavaScript disabled.
    def enrollment
      return head :not_found unless Rails::Runtime.config.lifecycle.enabled
      page("enrollment")
    end

    def prepare
      return head :not_found if mobile? && !Rails::Runtime.config.mobile.enabled
      if enrollment?
        return head :not_found unless Rails::Runtime.config.lifecycle.enabled
        @enrollment_identifier = Rails::Runtime.intake.call(identifier: params[:email_address], ip: request.remote_ip,
          action: :register, challenge_token: challenge_token)
        return provider_intake_failure(@enrollment_identifier) if @enrollment_identifier.is_a?(Symbol)
      else
        admitted = Rails::Runtime.intake.anonymous(ip: request.remote_ip, action: (params[:flow].to_s == "reauthenticate") ? :reauthenticate : :provider, challenge_token: challenge_token)
        return provider_intake_failure(admitted) if admitted.is_a?(Symbol)
      end
      if params[:flow].to_s == "link"
        elevation = Rails::Runtime.sessions.with_elevation(user: Current.user, session: Current.session,
          purpose: Core::ExternalIdentities::LINK, policy: Rails::Runtime.step_up_policy)
        return redirect_to "/reauthenticate?purpose=link_external_identity", status: :see_other unless elevation.success?
      end
      pending = service.begin_transaction(configuration_id: @provider.configuration.id,
        browser_secret: browser_secret, **transaction_subject)
      return provider_failure(pending.reason) unless pending.success?

      if mobile?
        accepted = Rails::Runtime.mobile_handoffs.begin_transaction(pending: pending.credential,
          client_id: params[:client_id], callback: params[:callback], state: params[:state],
          code_challenge: params[:code_challenge], code_challenge_method: params[:code_challenge_method])
        unless accepted.success?
          service.cancel(transaction: pending.credential.id, browser_secret: browser_secret)
          return provider_failure(accepted.reason)
        end
      end

      if enrollment? && !Rails::Runtime.provider_enrollment.write(pending: pending.credential,
        identifier: @enrollment_identifier, profile: registration_profile)
        service.cancel(transaction: pending.credential.id, browser_secret: browser_secret)
        return provider_failure(:invalid_credentials)
      end
      remember_correlation!(pending.credential)
      @provider_path = "/auth/#{@provider.middleware_name}"
      @omniauth_csrf_parameter = Rails::ProviderLibraries::RequestProtection.parameter
      @omniauth_csrf_token = Rails::ProviderLibraries::RequestProtection.token(session: request.env.fetch("rack.session"),
        rails_token: -> { form_authenticity_token })
      @heading = heading_for(pending.credential.purpose)
      # This token-free URL posts to the host's existing OAuth middleware.
      # Preserve its Rails origin check without sending a referrer off-site.
      response.set_header("Referrer-Policy", "same-origin")
      page("prepare")
    end

    # OmniAuth performs callback state/nonce/code validation. The correlation
    # middleware has attached the opaque Core transaction only after its
    # state check succeeds; no raw params, profile attributes, or tokens are
    # accepted here. Apple's signed callback cookie supplies that same opaque
    # data when its form_post cannot send the normal SameSite=Lax session.
    def callback
      correlation = request.env[correlation_env_key]
      return provider_failure(:invalid_credentials) unless valid_correlation?(correlation)
      return provider_failure(:invalid_credentials) unless correlation.fetch("configuration_id") == @provider.configuration.id

      pending = service.pending(transaction: correlation.fetch("transaction"), browser_secret: correlation.fetch("browser_secret"))
      return provider_failure(:invalid_credentials) unless pending && pending.configuration.equal?(@provider.configuration) &&
        pending.purpose.to_s == correlation.fetch("purpose")

      callback = Rails::ProviderLibraries::OmniAuth::CallbackResult.capture(env: request.env, provider: @provider.middleware_name)
      evidence = pending.configuration.verify(server_result: callback, transaction: pending)
      return provider_failure(:invalid_credentials) unless evidence

      case pending.purpose
      when Core::ExternalIdentities::MOBILE then finish_mobile(evidence)
      when Core::ExternalIdentities::ENROLL then finish_enrollment(pending, evidence)
      when :sign_in then finish_sign_in(evidence)
      when Core::ExternalIdentities::LINK then finish_link(pending, evidence)
      else finish_reauthentication(pending, evidence)
      end
    ensure
      Rails::Runtime.provider_enrollment.erase(pending: pending) if pending&.purpose == Core::ExternalIdentities::ENROLL
    end

    private

    def service = Rails::Runtime.external_identities

    def load_provider
      return head :not_found unless Rails::Runtime.config.external_identities.enabled

      @provider = Rails::Runtime.config.external_identities.providers.find { |item| item.middleware_name == params[:provider].to_s }
      head :not_found unless @provider
    end

    def sign_in? = params[:flow].to_s == "sign_in"
    def mobile? = params[:flow].to_s == "mobile"

    def enrollment? = params[:flow].to_s == "enroll"
    def anonymous_or_callback? = sign_in? || enrollment? || mobile? || action_name == "callback"
    def registration_profile = {}

    def transaction_subject
      return {purpose: Core::ExternalIdentities::MOBILE} if mobile?
      return {purpose: Core::ExternalIdentities::ENROLL} if enrollment?
      return {purpose: :sign_in} if sign_in?
      return {user: Current.user, session: Current.session, purpose: Core::ExternalIdentities::LINK} if params[:flow].to_s == "link"

      {user: Current.user, session: Current.session, purpose: params[:purpose].to_s}
    end

    def browser_secret
      session[:add_auth_browser] ||= Rails::Runtime.browser_binding.generate
    end

    def remember_correlation!(pending)
      if @provider.apple_form_post?
        Rails::ProviderLibraries::AppleFormPostCorrelation.remember!(session: session, transaction: pending.id,
          browser_secret: browser_secret, configuration_id: @provider.configuration.id, purpose: pending.purpose, remember: remember?)
      else
        Rails::ProviderLibraries::OmniAuthCorrelation.remember!(session: session, provider: @provider.middleware_name,
          transaction: pending.id, browser_secret: browser_secret, configuration_id: @provider.configuration.id, purpose: pending.purpose, remember: remember?)
      end
    end

    def correlation_env_key
      @provider.apple_form_post? ? "add_auth.apple_correlation" : Rails::ProviderLibraries::OmniAuthCorrelation::ENV_KEY
    end

    def valid_correlation?(value)
      value.is_a?(Hash) && %w[transaction browser_secret configuration_id purpose].all? do |key|
        value[key].is_a?(String) && value[key].valid_encoding? && value[key].bytesize.between?(1, 2048)
      end
    end

    def finish_enrollment(pending, evidence)
      intake = Rails::Runtime.provider_enrollment.read(pending: pending)
      return provider_failure(:invalid_credentials) unless intake
      result = Rails::Runtime.accounts.register_external(evidence: evidence, **intake)
      return provider_failure(result.reason) unless result.success?
      redirect_to "/account/check-email", status: :see_other
    end

    def provider_intake_failure(reason)
      status = {rate_limited: :too_many_requests, challenge_unavailable: :service_unavailable}.fetch(reason, :unprocessable_entity)
      @error = "This request could not be verified. Please try again shortly."
      response.set_header("Retry-After", "300") if %i[rate_limited challenge_unavailable].include?(reason)
      page("failure", status: status)
    end

    def finish_sign_in(evidence)
      result = service.sign_in(evidence: evidence, replacing: add_auth_replacement_session,
        **add_auth_session_hints.merge(remember: correlation_remember?))
      return provider_failure(result.reason) unless result.success?

      destination = after_authentication_url
      add_auth_accept(result.grant)
      redirect_to destination, status: :see_other
    end

    def finish_mobile(evidence)
      result = service.mobile_handoff(evidence: evidence, handoffs: Rails::Runtime.mobile_handoffs)
      return provider_failure(result.reason) unless result.success?
      handoff = result.credential
      redirect_to "#{handoff.callback}?#{URI.encode_www_form(code: handoff.code, state: handoff.state)}", status: :see_other, allow_other_host: true
    end

    def finish_link(pending, evidence)
      account, current = correlated_session(pending)
      return provider_failure(:elevation_required) unless account && current

      elevation = Rails::Runtime.sessions.with_elevation(user: account, session: current,
        purpose: Core::ExternalIdentities::LINK, policy: Rails::Runtime.step_up_policy)
      result = service.link(user: account, session: current, evidence: evidence, grant: elevation.credential)
      return provider_failure(result.reason) unless result.success?

      redirect_to "/account/external-identities", status: :see_other
    end

    def finish_reauthentication(pending, evidence)
      account, current = correlated_session(pending)
      return provider_failure(:elevation_required) unless account && current

      result = service.reauthenticate(user: account, session: current, evidence: evidence)
      return provider_failure(result.reason) unless result.success?

      grant = Rails::Runtime.sessions.rotate_for_step_up(user: account, session: current, grant: result.credential)
      return provider_failure(:elevation_required) unless grant

      add_auth_accept(grant)
      redirect_to Rails::Runtime.step_up_policy.return_to(pending.purpose), status: :see_other
    end

    # A form_post callback can correctly correlate an authenticated transaction
    # while lacking the normal app cookie. Rehydrate only the exact session row
    # recorded by Core; Core rechecks that row's digest and policy version under
    # lock before link/reauthentication can mutate authority.
    def correlated_session(pending)
      account = ::User.find_by(id: pending.user_id)
      current = account && ::Session.find_by(id: pending.session_id, user_id: account.id, token_digest: pending.session_digest)
      [account, current]
    end

    def provider_failure(_reason)
      @error = "We could not verify this provider sign-in. Please try again."
      page("failure", status: :unprocessable_entity)
    end

    def provider_unavailable
      @error = "Provider sign-in is temporarily unavailable. Please try again shortly."
      page("failure", status: :service_unavailable)
    end

    def heading_for(purpose)
      [:sign_in, Core::ExternalIdentities::ENROLL, Core::ExternalIdentities::MOBILE].include?(purpose) ? "Continue to #{@provider.label}" : "Confirm with #{@provider.label}"
    end

    def correlation_remember? = request.env[correlation_env_key].fetch("remember") == true

    def remember? = sign_in? && params[:remember].to_s == "1"

    def authentication_partial(partial) = "add_auth/provider_sign_ins/#{partial}"
  end
end
