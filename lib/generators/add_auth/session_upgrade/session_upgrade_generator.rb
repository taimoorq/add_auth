# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class SessionUpgradeGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      def shared_browser_runtime
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("add_auth/application.js")
          route 'get "add_auth/application.js", to: "add_auth/assets#application"'
        end
      end

      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def install_configuration
        invoke "add_auth:install"
      end

      def migration
        unless Dir[File.join(destination_root, "db/migrate/*_extend_sessions_for_add_auth.rb")].any?
          migration_template "extend_sessions_for_add_auth.rb.tt", "db/migrate/extend_sessions_for_add_auth.rb"
        end
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_elevation.rb")].any?
          migration_template "add_add_auth_elevation.rb.tt", "db/migrate/add_add_auth_elevation.rb"
        end
      end

      def assets_and_sign_in
        source = File.read(File.join(destination_root, "config/routes.rb"))
        {"add_auth.css" => "assets#stylesheet", "add_auth/turbo.js" => "assets#turbo",
         "add_auth/boot.js" => "assets#boot", "add_auth/stimulus.js" => "assets#stimulus", "add_auth/challenge.js" => "assets#challenge",
         "sign-in" => "sign_ins#new"}.each do |path, action|
          route %(get "#{path}", to: "add_auth/#{action}") unless source.include?(%("#{path}"))
        end
        route 'post "sign-in/password", to: "add_auth/sign_ins#password"' unless source.include?('"sign-in/password"')
      end

      def hooks
        path = "app/controllers/application_controller.rb"
        source = File.read(File.join(destination_root, path))
        unless source.include?("include Authentication")
          raise Thor::Error, "Expected ApplicationController to include Authentication; integrate AddAuth::Rails::Authentication after it manually."
        end
        unless source.include?("include AddAuth::Rails::Authentication")
          inject_into_file path, "\n  include AddAuth::Rails::Authentication", after: "include Authentication"
        end
        path = "app/models/user.rb"
        unless File.read(File.join(destination_root, path)).include?("include AddAuth::Rails::UserLifecycle")
          inject_into_file path, "  include AddAuth::Rails::UserLifecycle\n", after: /class User < [^\n]+\n/
        end
        path = "app/models/session.rb"
        unless File.read(File.join(destination_root, path)).include?("self.filter_attributes")
          inject_into_file path, "  self.filter_attributes += [:token_digest, :elevation_credential_id]\n", after: /class Session < [^\n]+\n/
        end
        path = "config/initializers/add_auth.rb"
        unless File.read(File.join(destination_root, path)).include?('require "add_auth/rails/authentication"')
          prepend_to_file path, %(require "add_auth/rails/authentication"\nrequire "add_auth/rails/user_lifecycle"\n)
        end
        gsub_file path, "# config.session.enabled = true", "config.session.enabled = true"
        routes = File.join(destination_root, "config/routes.rb")
        source = File.read(routes)
        unless source.include?("# AddAuth session management")
          route <<~ROUTES
            # AddAuth session management
            get "sessions/revoke-all", to: "add_auth/sessions#new_revoke_all"
            post "sessions/revoke-all", to: "add_auth/sessions#revoke_all"
            resources :security_sessions, path: "sessions", only: [:index, :destroy], controller: "add_auth/sessions"
          ROUTES
        end
      end
    end
  end
end
