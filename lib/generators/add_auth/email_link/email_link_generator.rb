# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class EmailLinkGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def dependencies
        invoke "add_auth:session_upgrade"
        invoke "add_auth:email_tokens"
      end

      def account_cleanup
        path = "app/models/user.rb"
        unless File.read(File.join(destination_root, path)).include?("has_many :add_auth_sign_in_tokens")
          inject_into_file path, "  has_many :add_auth_sign_in_tokens, dependent: :delete_all\n", after: /class User < [^\n]+\n/
        end
      end

      def outbox
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_email_delivery.rb")].any?
          migration_template "add_add_auth_email_delivery.rb.tt", "db/migrate/add_add_auth_email_delivery.rb"
        end
      end

      def browser_binding
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_email_binding.rb")].any?
          migration_template "add_add_auth_email_binding.rb.tt", "db/migrate/add_add_auth_email_binding.rb"
        end
      end

      def routes_and_styles
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("# AddAuth sign-in")
          route <<~ROUTES
            # AddAuth sign-in
            post "sign-in/email", to: "add_auth/sign_ins#request_link"
            get "sign-in/check-email", to: "add_auth/sign_ins#check_email"
            get "sign-in/link", to: "add_auth/sign_ins#link"
            post "sign-in/link", to: "add_auth/sign_ins#confirm"
          ROUTES
        end
        unless File.read(File.join(destination_root, "config/routes.rb")).include?("add_auth/challenge.js")
          route 'get "add_auth/challenge.js", to: "add_auth/assets#challenge"'
        end
        gsub_file "config/initializers/add_auth.rb", "# config.email_link.enabled = true", "config.email_link.enabled = true"
        say "Review and migrate, configure base_url/mail_from, a durable queue, shared rate-limit cache and a recurring add_auth:deliver_pending sweep."
      end
    end
  end
end
