# frozen_string_literal: true

module Latchkey
  module SignInsHelper
    def latchkey_stylesheet
      path = Latchkey.configuration.stylesheet
      raise Latchkey::Error, "authentication stylesheets must use a same-origin path" if path && !Core::Sessions.safe_return(path)
      path
    end

    def latchkey_class(role)
      Latchkey.configuration.css_classes.fetch(role, "latchkey-#{role}")
    end

    def latchkey_challenge_form_data(action)
      data = {turbo_frame: "_top"}
      return data unless Latchkey.configuration.challenge_on.include?(action)
      provider = Latchkey.configuration.challenge
      return data unless provider.site_key
      kind = case provider
      when Core::Challenge::Turnstile then "turnstile"
      when Core::Challenge::Recaptcha then "recaptcha-#{provider.version}"
      else return data
      end
      data.merge(controller: "latchkey-challenge",
        action: "submit->latchkey-challenge#submit latchkey:proof-used->latchkey-challenge#reset turbo:submit-end->latchkey-challenge#reset turbo:before-cache@document->latchkey-challenge#beforeCache",
        latchkey_challenge_provider_value: kind, latchkey_challenge_site_key_value: provider.site_key,
        latchkey_challenge_action_value: (provider.respond_to?(:expected_action) && provider.expected_action) || action,
        latchkey_challenge_script_url_value: provider.script_url)
    end

    def latchkey_challenge_tag(action, id: action)
      return safe_join([]) unless Latchkey.configuration.challenge_on.include?(action)
      safe_join([
        hidden_field_tag(:challenge_token, nil, id: "#{id}_challenge_token", data: {latchkey_challenge_target: "token"}),
        tag.div(hidden: true, data: {latchkey_challenge_target: "widget"}),
        tag.p("Verification is loading.", hidden: true, role: "status", class: latchkey_class(:notice),
          data: {latchkey_challenge_target: "status"})
      ])
    end
  end
end
