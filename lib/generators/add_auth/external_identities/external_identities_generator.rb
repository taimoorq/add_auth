# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module AddAuth
  module Generators
    # Optional persistence and routes; provider strategies remain disabled until configured.
    class ExternalIdentitiesGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      def self.next_migration_number(dirname) = ::ActiveRecord::Generators::Base.next_migration_number(dirname)

      def persistence
        unless Dir[File.join(destination_root, "db/migrate/*_create_add_auth_external_identities.rb")].any?
          migration_template "create_add_auth_external_identities.rb.tt", "db/migrate/create_add_auth_external_identities.rb"
        end
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_external_identity_validity.rb")].any?
          migration_template "add_add_auth_external_identity_validity.rb.tt", "db/migrate/add_add_auth_external_identity_validity.rb"
        end
        unless Dir[File.join(destination_root, "db/migrate/*_add_add_auth_external_enrollment.rb")].any?
          migration_template "add_add_auth_external_enrollment.rb.tt", "db/migrate/add_add_auth_external_enrollment.rb"
        end
        %w[external_identity external_transaction].each do |name|
          copy_file "add_auth_#{name}.rb", "app/models/add_auth_#{name}.rb", skip: true
        end
      end

      def routes
        source = File.read(File.join(destination_root, "config/routes.rb"))
        return if source.include?("# AddAuth external provider callbacks")

        route <<~ROUTES
          # AddAuth external provider callbacks
          get "account/sign-up/providers/:provider", to: "add_auth/provider_sign_ins#enrollment", defaults: {flow: "enroll"}
          post "account/sign-up/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "enroll"}
          post "sign-in/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "sign_in"}
          post "account/external-identities/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "link"}
          get "account/external-identities", to: "add_auth/external_identities#index"
          delete "account/external-identities/:id", to: "add_auth/external_identities#destroy"
          post "reauthenticate/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "reauthenticate"}
          match "auth/:provider/callback", to: "add_auth/provider_sign_ins#callback", via: [:get, :post], constraints: AddAuth::Rails::ProviderLibraries::CallbackRoute
        ROUTES
      end

      def provider_configuration
        copy_file "providers.rb", "config/initializers/add_auth_providers.rb", skip: true
      end
    end
  end
end
