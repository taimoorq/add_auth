# frozen_string_literal: true

module AddAuth
  module SignInsHelper
    def add_auth_stylesheet
      path = AddAuth.configuration.stylesheet
      raise AddAuth::Error, "authentication stylesheets must use a same-origin path" if path && !Core::Sessions.safe_return(path)
      path
    end

    def add_auth_class(role)
      AddAuth.configuration.css_classes.fetch(role, "add_auth-#{role}")
    end

    def add_auth_challenge_form_data(action)
      data = {turbo_frame: "_top"}
      data[:turbo] = false unless AddAuth.configuration.turbo_enabled
      return data unless AddAuth.configuration.challenge_on.include?(action)
      provider = AddAuth.configuration.challenge
      return data unless provider.site_key
      kind = case provider
      when Core::Challenge::Turnstile then "turnstile"
      when Core::Challenge::Recaptcha then "recaptcha-#{provider.version}"
      else return data
      end
      data.merge(controller: "add-auth-challenge",
        action: "submit->add-auth-challenge#submit add_auth:proof-used->add-auth-challenge#reset turbo:submit-end->add-auth-challenge#reset turbo:before-cache@document->add-auth-challenge#beforeCache pagehide@window->add-auth-challenge#beforeCache pageshow@window->add-auth-challenge#restore",
        add_auth_challenge_provider_value: kind, add_auth_challenge_site_key_value: provider.site_key,
        add_auth_challenge_action_value: (provider.respond_to?(:expected_action) && provider.expected_action) || action,
        add_auth_challenge_script_url_value: provider.script_url)
    end

    def add_auth_challenge_tag(action, id: action)
      return safe_join([]) unless AddAuth.configuration.challenge_on.include?(action)
      safe_join([
        hidden_field_tag(:challenge_token, nil, id: "#{id}_challenge_token", data: {add_auth_challenge_target: "token"}),
        tag.div(hidden: true, data: {add_auth_challenge_target: "widget"}),
        tag.p("Verification is loading.", hidden: true, role: "status", class: add_auth_class(:notice),
          data: {add_auth_challenge_target: "status"})
      ])
    end
  end
end
