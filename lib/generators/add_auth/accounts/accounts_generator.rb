# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class AccountsGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      desc "Prepare optional account lifecycle schema and pages; review existing account confirmation and policy before enabling"

      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def prerequisites
        invoke "add_auth:notifications"
        invoke "add_auth:step_up"
      end

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_accounts.rb")].any?
          migration_template "add_add_auth_accounts.rb.tt", "db/migrate/add_add_auth_accounts.rb"
        end
        %w[add_auth_account_token add_auth_address_claim].each do |name|
          template "#{name}.rb", "app/models/#{name}.rb" unless File.exist?(File.join(destination_root, "app/models/#{name}.rb"))
        end
        say "Account lifecycle is prepared but disabled. Map existing account policy and confirmation state, then set config.lifecycle.enabled = true."
      end

      def routes
        return if File.read(File.join(destination_root, "config/routes.rb")).include?("# AddAuth account lifecycle")
        route <<~ROUTES
          # AddAuth account lifecycle
          get "account/sign-up", to: "add_auth/accounts#new"
          post "account/sign-up", to: "add_auth/accounts#create"
          get "account/check-email", to: "add_auth/accounts#check_email"
          get "account/requests/:purpose", to: "add_auth/accounts#request_form", constraints: {purpose: /confirm|reset_password|unlock/}
          post "account/requests/:purpose", to: "add_auth/accounts#request_proof", constraints: {purpose: /confirm|reset_password|unlock/}
          get "account/proofs/:purpose", to: "add_auth/accounts#proof", constraints: {purpose: /confirm|reset_password|unlock/}
          post "account/proofs/:purpose", to: "add_auth/accounts#consume", constraints: {purpose: /confirm|reset_password|unlock/}
          get "account/email", to: "add_auth/accounts#edit_email"
          post "account/email", to: "add_auth/accounts#change_email"
          get "account/password", to: "add_auth/accounts#edit_password"
          post "account/password", to: "add_auth/accounts#change_password"
          get "account/delete", to: "add_auth/accounts#confirm_deletion"
          delete "account", to: "add_auth/accounts#destroy"
        ROUTES
      end
    end
  end
end
