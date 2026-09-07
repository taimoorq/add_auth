# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Latchkey
  module Generators
    class StepUpGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies
        invoke "latchkey:email_link"
      end

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_add_latchkey_reauthentication.rb")].any?
          migration_template "add_latchkey_reauthentication.rb.tt", "db/migrate/add_latchkey_reauthentication.rb"
        end
      end

      def wiring
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("# Latchkey reauthentication")
          route <<~ROUTES
            # Latchkey reauthentication
            get "reauthenticate", to: "latchkey/reauthentications#new"
            post "reauthenticate/password", to: "latchkey/reauthentications#password"
            post "reauthenticate/email", to: "latchkey/reauthentications#request_link"
            get "reauthenticate/check-email", to: "latchkey/reauthentications#check_email"
            get "reauthenticate/link", to: "latchkey/reauthentications#link"
            post "reauthenticate/link", to: "latchkey/reauthentications#confirm"
          ROUTES
        end
        initializer = "config/initializers/latchkey.rb"
        unless File.read(File.join(destination_root, initializer)).include?("config.step_up.enabled = true")
          append_to_file initializer, "\nLatchkey.configure do |config|\n  config.step_up.enabled = true\n  # Declare purpose methods and a fixed safe GET return_to before use.\nend\n"
        end
        say "Migrate and declare config.step_up.purposes. Use with_elevated_session around sensitive database mutations."
      end
    end
  end
end
