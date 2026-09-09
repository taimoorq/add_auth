# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    class DeviseAccountsGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      desc "Prepare additive account columns for a reviewed Devise migration; does not convert accounts or switch authentication"

      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def migration
        return if Dir[File.join(destination_root, "db/migrate/*_prepare_add_auth_devise_accounts.rb")].any?
        migration_template "prepare_add_auth_devise_accounts.rb.tt", "db/migrate/prepare_add_auth_devise_accounts.rb"
        say "Review the generated migration and run preflight before conversion. Authentication and host models are unchanged."
      end
    end
  end
end
