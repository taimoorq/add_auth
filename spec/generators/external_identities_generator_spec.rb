# frozen_string_literal: true

require "rails_helper"
require_relative "../support/isolated_host"

RSpec.describe "Optional external identity persistence in a fresh host" do
  it "generates additive key-aware persistence twice and preserves ordinary Rails sign-in" do
    Dir.mktmpdir("add-auth-external-host-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: ["pg"])
      if ENV["ADD_AUTH_EXTERNAL_DATABASE_URL"]
        require "pg"
        url = ENV.fetch("ADD_AUTH_EXTERNAL_DATABASE_URL")
        abort "isolated external identity database required" unless URI.parse(url).path == "/add_auth_external_test"
        connection = PG.connect(url)
        connection.exec("CREATE SCHEMA IF NOT EXISTS g4_uuid")
        host.environment["DATABASE_URL"] = "#{url}?schema_search_path=g4_uuid"
      end
      host.run("generate", "authentication")
      if connection
        user_migration = Dir[File.join(host.root, "db/migrate/*_create_users.rb")].fetch(0)
        session_migration = Dir[File.join(host.root, "db/migrate/*_create_sessions.rb")].fetch(0)
        File.write(user_migration, File.read(user_migration).sub("create_table :users do", "create_table :users, id: :uuid do"))
        File.write(session_migration, File.read(session_migration).sub("t.references :user,", "t.references :user, type: :uuid,"))
      end
      route_path = File.join(host.root, "config/routes.rb")
      File.write(route_path, File.read(route_path).sub("Rails.application.routes.draw do", <<~RUBY.chomp))
        Rails.application.routes.draw do
          root "sessions#new"
          match "auth/host_provider/callback", via: [:get, :post], to: ->(_env) { [200, {"content-type" => "text/plain"}, ["host callback retained"]] }
      RUBY
      host.run("generate", "add_auth:external_identities")
      routes = File.read(File.join(host.root, "config/routes.rb"))
      host.run("generate", "add_auth:external_identities")
      expect(File.read(File.join(host.root, "config/routes.rb"))).to eq(routes)
      expect(Dir[File.join(host.root, "db/migrate/*_create_add_auth_external_identities.rb")].size).to eq(1)
      host.run("db:migrate")
      expect(host.runner(<<~RUBY)).to include("external persistence host verified")
        abort "provider integration unexpectedly enabled" if defined?(OmniAuth)
        user = User.create!(email_address: "stock@example.test", password: "correct-password")
        binding = AddAuthExternalIdentity.create!(user: user, namespace: "a" * 64, provider_id: "fixture",
          issuer: "https://issuer.test", audience: "web", subject: "ExactSubject", provenance: "fixture", credential_version: "v1", linked_at: Time.now)
        abort "owner reference changed" unless binding.reload.user_id == user.id
        client = ActionDispatch::Integration::Session.new(Rails.application)
        [false, true].each do |enabled|
          AddAuth.configuration.external_identities.enabled = enabled
          client.get "/auth/host_provider/callback"
          abort "host callback intercepted" unless client.response.status == 200 && client.response.body == "host callback retained"
        end
        AddAuth.configuration.external_identities.enabled = false
        client.get "/session/new"
        abort "ordinary sign-in page broken" unless client.response.status == 200
        client.post "/session", params: {email_address: user.email_address, password: "correct-password"}
        abort "ordinary password sign-in broken" unless client.response.redirect? && Session.count == 1
        abort "missing session version columns" unless Session.column_names.include?("authentication_external_version")
        puts "external persistence host verified"
      RUBY
    ensure
      connection&.exec("DROP SCHEMA IF EXISTS g4_uuid CASCADE")
      connection&.close
    end
  end
end
