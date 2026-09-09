# frozen_string_literal: true

require "spec_helper"
require "rails"
require_relative "../support/isolated_host"

RSpec.describe "Atomic external enrollment in a fresh Rails host" do
  it "shares G3 account creation, validations, claims and proof rollback without granting sessions" do
    Dir.mktmpdir("add-auth-external-enrollment-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: ["pg"])
      if ENV["ADD_AUTH_EXTERNAL_DATABASE_URL"]
        require "pg"
        url = ENV.fetch("ADD_AUTH_EXTERNAL_DATABASE_URL")
        abort "isolated external identity database required" unless URI.parse(url).path == "/add_auth_external_test"
        connection = PG.connect(url)
        connection.exec("CREATE SCHEMA g4_enrollment")
        host.environment["DATABASE_URL"] = "#{url}?schema_search_path=g4_enrollment"
      end
      host.run("generate", "authentication")
      host.run("generate", "add_auth:accounts")
      host.run("generate", "add_auth:external_identities")
      host.run("generate", "migration", "AddEnrollmentProfileToUsers", "name:string", "accepted_terms:boolean")
      migration = Dir[File.join(host.root, "db/migrate/*_add_enrollment_profile_to_users.rb")].fetch(0)
      File.write(migration, File.read(migration).sub("def change", "def change\n    change_column_null :users, :password_digest, true"))
      stock_user_source = File.read(File.join(host.root, "app/models/user.rb"))
      File.write(File.join(host.root, "app/models/user.rb"), <<~RUBY)
        class User < ApplicationRecord
          has_secure_password validations: false
          has_many :sessions, dependent: :destroy
          normalizes :email_address, with: ->(email) { email.strip.downcase }
          validates :email_address, :name, presence: true
          validates :email_address, uniqueness: true
          validates :accepted_terms, inclusion: {in: [true]}
        end
      RUBY
      host.configure
      host.run("db:migrate")
      source = File.read(File.expand_path("../support/external_enrollment_journey.rb", __dir__))
      expect(host.runner(source)).to include("external enrollment and rollback verified")
      File.write(File.join(host.root, "app/models/user.rb"), stock_user_source)
      expect(host.runner(<<~RUBY)).to include("stock passwordless rejection verified")
        require "add_auth/core/account_lifecycle"
        require "add_auth/rails/stores/account_tokens"
        before = User.count
        store = AddAuth::Rails::Stores::AccountTokens.new(user_model: User, token_model: AddAuthAccountToken,
          session_model: Session, address_model: AddAuthAddressClaim, authority: nil, provision: ->(_) {})
        result = store.create_account(email: "stock-rejected@example.test", password: nil) { abort "stock host accepted passwordless creation" }
        abort "stock validation bypassed" unless result == :invalid && User.count == before
        puts "stock passwordless rejection verified"
      RUBY
    ensure
      connection&.exec("DROP SCHEMA IF EXISTS g4_enrollment CASCADE")
      connection&.close
    end
  end
end
