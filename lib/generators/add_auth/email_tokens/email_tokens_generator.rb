# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    # Internal persistence foundation only. Does not install sign-in routes.
    class EmailTokensGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      def self.next_migration_number(dirname)
        ::ActiveRecord::Generators::Base.next_migration_number(dirname)
      end

      def create_token_model
        unless File.file?(File.join(destination_root, "app/models/user.rb"))
          raise Thor::Error, "Run the Rails authentication generator first."
        end
        return if File.exist?(File.join(destination_root, "app/models/add_auth_sign_in_token.rb"))

        copy_file "add_auth_sign_in_token.rb", "app/models/add_auth_sign_in_token.rb"
      end

      def create_token_migration
        return if Dir[File.join(destination_root, "db/migrate/*_create_add_auth_sign_in_tokens.rb")].any?

        migration_template "create_add_auth_sign_in_tokens.rb.tt",
          "db/migrate/create_add_auth_sign_in_tokens.rb"
      end
    end
  end
end
