# frozen_string_literal: true

require "latchkey/rails/ejection"

module Latchkey
  # Fixed gem assets only. This works even in hosts without an asset pipeline.
  class AssetsController < ActionController::Base
    # These GET-only routes expose fixed public files, never session data.
    skip_forgery_protection
    before_action { response.set_header("Cross-Origin-Resource-Policy", "same-origin") }
    def stylesheet
      expires_in 1.hour, public: true
      send_file Rails::Engine.root.join("lib/generators/latchkey/email_link/templates/latchkey.css"),
        type: "text/css", disposition: "inline"
    end

    def boot
      source = 'if (!window.Turbo) await import("/latchkey/turbo.js"); await import("/latchkey/challenge.js");'
      source += ' await import("/latchkey/passkey.js");' if Rails::Runtime.config.passkeys.enabled
      render body: source, content_type: "text/javascript"
    end

    def turbo
      expires_in 1.hour, public: true
      source = File.read(Gem.loaded_specs.fetch("turbo-rails").full_gem_path + "/app/assets/javascripts/turbo.min.js")
      render body: source, content_type: "text/javascript"
    end

    def stimulus
      expires_in 1.hour, public: true
      source = File.read(Gem.loaded_specs.fetch("stimulus-rails").full_gem_path + "/app/assets/javascripts/stimulus.min.js")
      render body: source, content_type: "text/javascript"
    end

    %w[application codec passkey].each do |asset|
      define_method(asset) do
        expires_in 1.hour, public: true
        send_file Rails::Ejection.new(host_root: ::Rails.root).asset(asset),
          type: "text/javascript", disposition: "inline"
      end
    end

    def challenge
      expires_in 1.hour, public: true
      send_file Rails::Ejection.new(host_root: ::Rails.root).asset("challenge"),
        type: "text/javascript", disposition: "inline"
    end
  end
end
