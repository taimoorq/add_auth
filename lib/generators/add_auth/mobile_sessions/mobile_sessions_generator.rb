# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class MobileSessionsGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_mobile_sessions.rb")].any?
          migration_template "add_add_auth_mobile_sessions.rb.tt", "db/migrate/add_add_auth_mobile_sessions.rb"
        end
        unless Dir[File.join(destination_root, "db/migrate/*_create_add_auth_mobile_handoffs.rb")].any?
          migration_template "create_add_auth_mobile_handoffs.rb.tt", "db/migrate/create_add_auth_mobile_handoffs.rb"
        end
        copy_file "add_auth_mobile_handoff.rb", "app/models/add_auth_mobile_handoff.rb", skip: true
      end

      def routes
        source = File.read(File.join(destination_root, "config/routes.rb"))
        return if source.include?("# AddAuth mobile sessions")
        route <<~ROUTES
          # AddAuth mobile sessions
          post "mobile/session", to: "add_auth/mobile_sessions#create"
          get "mobile/session", to: "add_auth/mobile_sessions#show"
          delete "mobile/session", to: "add_auth/mobile_sessions#destroy"
          get "mobile/sessions", to: "add_auth/mobile_sessions#index"
          delete "mobile/sessions/:id", to: "add_auth/mobile_sessions#revoke"
          post "mobile/sessions/revoke-all", to: "add_auth/mobile_sessions#revoke_all"
          get "mobile/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "mobile"}
          post "mobile/handoff", to: "add_auth/mobile_sessions#exchange"
          post "mobile/apple/challenge", to: "add_auth/mobile_sessions#apple_challenge"
          post "mobile/apple/session", to: "add_auth/mobile_sessions#apple"
          post "mobile/apple/enrollment", to: "add_auth/mobile_sessions#apple_enroll"
        ROUTES
      end

      def configuration
        copy_file "mobile.rb", "config/initializers/add_auth_mobile.rb", skip: true
      end
    end
  end
end
