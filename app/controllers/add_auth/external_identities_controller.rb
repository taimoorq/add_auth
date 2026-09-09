# frozen_string_literal: true

module AddAuth
  class ExternalIdentitiesController < ::ApplicationController
    include Rails::AuthenticationPages

    skip_before_action :require_authentication, raise: false
    before_action :private_response
    before_action :require_feature
    before_action :require_add_auth_authentication
    protect_from_forgery with: :exception
    helper AddAuth::SignInsHelper
    layout "add_auth/authentication"
    rescue_from AddAuth::Error, with: :unavailable

    def index
      load_identities
      page("index")
    end

    def destroy
      elevation = Rails::Runtime.sessions.with_elevation(user: Current.user, session: Current.session,
        purpose: Core::ExternalIdentities::UNLINK, policy: Rails::Runtime.step_up_policy)
      result = service.unlink(user: Current.user, session: Current.session, identity_id: params[:id], grant: elevation.credential)
      if result.success?
        redirect_to "/account/external-identities", status: :see_other
      elsif result.reason == :elevation_required
        redirect_to "/reauthenticate?purpose=unlink_external_identity", status: :see_other
      else
        @error = (result.reason == :last_credential) ? "Add another usable sign-in method before removing this one." : "This sign-in method could not be changed. Try again."
        load_identities
        page("index", status: :unprocessable_entity)
      end
    end

    private

    def service = Rails::Runtime.external_identities

    def require_feature
      head :not_found unless Rails::Runtime.config.external_identities.enabled
    end

    def authentication_partial(partial) = "add_auth/external_identities/#{partial}"

    def load_identities
      @identities = ::AddAuthExternalIdentity.where(user_id: Current.user.id, revoked_at: nil).order(:linked_at)
      @providers = Rails::Runtime.config.external_identities.providers
    end

    def unavailable
      @error = "External sign-in is temporarily unavailable."
      page("unavailable", status: :service_unavailable)
    end
  end
end
