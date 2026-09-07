# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Latchkey
  module Generators
    class NotificationsGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies = invoke("latchkey:session_upgrade")

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_create_latchkey_security_events.rb")].any?
          migration_template "create_latchkey_security_events.rb.tt", "db/migrate/create_latchkey_security_events.rb"
        end
        copy_file "latchkey_security_event.rb", "app/models/latchkey_security_event.rb", skip: true
      end

      def configuration
        path = "config/initializers/latchkey.rb"
        unless File.read(File.join(destination_root, path)).include?("config.notifications.enabled = true")
          append_to_file path, "\nLatchkey.configure do |config|\n  config.notifications.enabled = true\nend\n"
        end
        say "Migrate, configure mail_from and a durable queue, and schedule latchkey:deliver_pending every minute."
      end
    end
  end
end
