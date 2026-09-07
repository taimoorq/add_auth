# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class NotificationsGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies = invoke("add_auth:session_upgrade")

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_create_add_auth_security_events.rb")].any?
          migration_template "create_add_auth_security_events.rb.tt", "db/migrate/create_add_auth_security_events.rb"
        end
        copy_file "add_auth_security_event.rb", "app/models/add_auth_security_event.rb", skip: true
      end

      def configuration
        path = "config/initializers/add_auth.rb"
        unless File.read(File.join(destination_root, path)).include?("config.notifications.enabled = true")
          append_to_file path, "\nAddAuth.configure do |config|\n  config.notifications.enabled = true\nend\n"
        end
        say "Migrate, configure mail_from and a durable queue, and schedule add_auth:deliver_pending every minute."
      end
    end
  end
end
