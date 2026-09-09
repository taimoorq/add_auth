# frozen_string_literal: true

require "rails_helper"
require "generators/add_auth/external_identities/external_identities_generator"
require "add_auth/rails/stores/external_identities"

AddAuth::Generators::ExternalIdentitiesGenerator.start([], destination_root: Rails.root.to_s, quiet: true)
# This optional URL names a disposable feature database, never an application
# database. The normal suite otherwise uses spec/dummy's selected test database.
if ENV["ADD_AUTH_EXTERNAL_DATABASE_URL"]
  url = URI.parse(ENV.fetch("ADD_AUTH_EXTERNAL_DATABASE_URL"))
  abort "isolated external identity database required" unless %w[postgres postgresql].include?(url.scheme) && url.path == "/add_auth_external_test"
  ActiveRecord::Base.establish_connection(ENV.fetch("ADD_AUTH_EXTERNAL_DATABASE_URL"))
end
ActiveRecord::MigrationContext.new(Rails.root.join("db/migrate")).migrate
require Rails.root.join("app/models/add_auth_external_identity").to_s
require Rails.root.join("app/models/add_auth_external_transaction").to_s
AddAuthExternalTransaction.reset_column_information
AddAuthExternalIdentity.reset_column_information
Session.reset_column_information
User.reset_column_information
