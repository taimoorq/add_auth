# frozen_string_literal: true

require "rails/generators"
require "generators/add_auth/feature_configuration"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class StepUpGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration
      include FeatureConfiguration

      source_root File.expand_path("templates", __dir__)
      class_option :email_link, type: :boolean, default: true, desc: "Enable email sign-in alongside reauthentication"
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies
        invoke "add_auth:email_link", [], enable: options[:email_link]
      end

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_reauthentication.rb")].any?
          migration_template "add_add_auth_reauthentication.rb.tt", "db/migrate/add_add_auth_reauthentication.rb"
        end
      end

      def wiring
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("# AddAuth reauthentication")
          route <<~ROUTES
            # AddAuth reauthentication
            get "reauthenticate", to: "add_auth/reauthentications#new"
            post "reauthenticate/password", to: "add_auth/reauthentications#password"
            post "reauthenticate/email", to: "add_auth/reauthentications#request_link"
            get "reauthenticate/check-email", to: "add_auth/reauthentications#check_email"
            get "reauthenticate/link", to: "add_auth/reauthentications#link"
            post "reauthenticate/link", to: "add_auth/reauthentications#confirm"
          ROUTES
        end
        enable_feature(:step_up)
        say "Migrate and declare config.step_up.purposes. Use with_elevated_session around sensitive database mutations."
      end
    end
  end
end
