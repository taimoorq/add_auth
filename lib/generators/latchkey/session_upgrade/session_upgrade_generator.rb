# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Latchkey
  module Generators
    class SessionUpgradeGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      def shared_browser_runtime
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("latchkey/application.js")
          route 'get "latchkey/application.js", to: "latchkey/assets#application"'
        end
      end

      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def install_configuration
        invoke "latchkey:install"
      end

      def migration
        unless Dir[File.join(destination_root, "db/migrate/*_extend_sessions_for_latchkey.rb")].any?
          migration_template "extend_sessions_for_latchkey.rb.tt", "db/migrate/extend_sessions_for_latchkey.rb"
        end
        unless Dir[File.join(destination_root, "db/migrate/*_add_latchkey_elevation.rb")].any?
          migration_template "add_latchkey_elevation.rb.tt", "db/migrate/add_latchkey_elevation.rb"
        end
      end

      def assets_and_sign_in
        source = File.read(File.join(destination_root, "config/routes.rb"))
        {"latchkey.css" => "assets#stylesheet", "latchkey/turbo.js" => "assets#turbo",
         "latchkey/boot.js" => "assets#boot", "latchkey/stimulus.js" => "assets#stimulus", "latchkey/challenge.js" => "assets#challenge",
         "sign-in" => "sign_ins#new"}.each do |path, action|
          route %(get "#{path}", to: "latchkey/#{action}") unless source.include?(%("#{path}"))
        end
        route 'post "sign-in/password", to: "latchkey/sign_ins#password"' unless source.include?('"sign-in/password"')
      end

      def hooks
        path = "app/controllers/application_controller.rb"
        source = File.read(File.join(destination_root, path))
        unless source.include?("include Authentication")
          raise Thor::Error, "Expected ApplicationController to include Authentication; integrate Latchkey::Rails::Authentication after it manually."
        end
        unless source.include?("include Latchkey::Rails::Authentication")
          inject_into_file path, "\n  include Latchkey::Rails::Authentication", after: "include Authentication"
        end
        path = "app/models/user.rb"
        unless File.read(File.join(destination_root, path)).include?("include Latchkey::Rails::UserLifecycle")
          inject_into_file path, "  include Latchkey::Rails::UserLifecycle\n", after: /class User < [^\n]+\n/
        end
        path = "app/models/session.rb"
        unless File.read(File.join(destination_root, path)).include?("self.filter_attributes")
          inject_into_file path, "  self.filter_attributes += [:token_digest, :elevation_credential_id]\n", after: /class Session < [^\n]+\n/
        end
        path = "config/initializers/latchkey.rb"
        unless File.read(File.join(destination_root, path)).include?('require "latchkey/rails/authentication"')
          prepend_to_file path, %(require "latchkey/rails/authentication"\nrequire "latchkey/rails/user_lifecycle"\n)
        end
        gsub_file path, "# config.session.enabled = true", "config.session.enabled = true"
        routes = File.join(destination_root, "config/routes.rb")
        source = File.read(routes)
        unless source.include?("# Latchkey session management")
          route <<~ROUTES
            # Latchkey session management
            get "sessions/revoke-all", to: "latchkey/sessions#new_revoke_all"
            post "sessions/revoke-all", to: "latchkey/sessions#revoke_all"
            resources :security_sessions, path: "sessions", only: [:index, :destroy], controller: "latchkey/sessions"
          ROUTES
        end
      end
    end
  end
end
