# frozen_string_literal: true

require "rails/generators"

module AddAuth
  module Generators
    # `bin/rails g add_auth:challenge turnstile` (or `recaptcha`) writes an
    # opt-in initializer without touching the host's existing initializer.
    class ChallengeGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)
      argument :provider, type: :string, required: true, banner: "turnstile|recaptcha"
      class_option :version, type: :string, default: "v3", desc: "reCAPTCHA version (v2 or v3)"

      def validate_provider
        return if %w[turnstile recaptcha].include?(provider.to_s.downcase)

        raise Thor::Error, "Choose a challenge provider: turnstile or recaptcha."
      end

      def validate_version
        return if provider.to_s.downcase == "turnstile"
        return if %w[v2 v3].include?(options[:version].to_s.downcase)

        raise Thor::Error, "reCAPTCHA version must be v2 or v3."
      end

      def create_initializer
        path = File.join(destination_root, "config/initializers/add_auth_challenge.rb")
        if File.exist?(path)
          say "Skipping #{path}; review the existing challenge configuration.", :yellow
          return
        end

        empty_directory "config/initializers"
        template "#{provider.to_s.downcase}.rb.tt", path
        say "Challenge server verification configured for #{provider}. Review environment keys and allowed hostnames."
      end

      def add_route
        path = File.join(destination_root, "config/routes.rb")
        return unless File.file?(path)
        return if File.read(path).include?("add_auth/challenge.js")

        route 'get "add_auth/challenge.js", to: "add_auth/assets#challenge"'
      end
    end
  end
end
