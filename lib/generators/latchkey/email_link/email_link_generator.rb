# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Latchkey
  module Generators
    class EmailLinkGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies
        invoke "latchkey:session_upgrade"
        invoke "latchkey:email_tokens"
      end

      def account_cleanup
        path = "app/models/user.rb"
        unless File.read(File.join(destination_root, path)).include?("has_many :latchkey_sign_in_tokens")
          inject_into_file path, "  has_many :latchkey_sign_in_tokens, dependent: :delete_all\n", after: /class User < [^\n]+\n/
        end
      end

      def outbox
        unless Dir[File.join(destination_root, "db/migrate/*_add_latchkey_email_delivery.rb")].any?
          migration_template "add_latchkey_email_delivery.rb.tt", "db/migrate/add_latchkey_email_delivery.rb"
        end
      end

      def browser_binding
        unless Dir[File.join(destination_root, "db/migrate/*_add_latchkey_email_binding.rb")].any?
          migration_template "add_latchkey_email_binding.rb.tt", "db/migrate/add_latchkey_email_binding.rb"
        end
      end

      def routes_and_styles
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("# Latchkey sign-in")
          route <<~ROUTES
            # Latchkey sign-in
            post "sign-in/email", to: "latchkey/sign_ins#request_link"
            get "sign-in/check-email", to: "latchkey/sign_ins#check_email"
            get "sign-in/link", to: "latchkey/sign_ins#link"
            post "sign-in/link", to: "latchkey/sign_ins#confirm"
          ROUTES
        end
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("latchkey/challenge.js")
          route 'get "latchkey/challenge.js", to: "latchkey/assets#challenge"'
        end
        gsub_file "config/initializers/latchkey.rb", "# config.email_link.enabled = true", "config.email_link.enabled = true"
        say "Review and migrate, configure base_url/mail_from, a durable queue, shared rate-limit cache and a recurring latchkey:deliver_pending sweep."
      end
    end
  end
end
