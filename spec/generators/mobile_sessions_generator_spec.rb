# frozen_string_literal: true

require "rails_helper"
require_relative "../support/isolated_host"

RSpec.describe "Optional mobile sessions in an installed-package host" do
  it "generates twice, stays dormant, then authenticates both separate transports with one revocation policy" do
    Dir.mktmpdir("add-auth-mobile-host-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate")
      host.run("generate", "authentication")
      host.run("generate", "add_auth:session_upgrade")
      host.run("generate", "add_auth:mobile_sessions")
      routes = File.read(File.join(host.root, "config/routes.rb"))
      host.run("generate", "add_auth:mobile_sessions")
      expect(File.read(File.join(host.root, "config/routes.rb"))).to eq(routes)
      expect(Dir[File.join(host.root, "db/migrate/*_add_add_auth_mobile_sessions.rb")].length).to eq(1)
      host.run("db:migrate")
      host.configure
      expect(host.runner(<<~RUBY)).to include("mobile package host verified")
        abort "optional provider libraries loaded" if defined?(OmniAuth)
        abort "mobile enabled by generator" if AddAuth.configuration.mobile.enabled
        user = User.create!(email_address: "native@example.test", password: "correct-password")
        client = ActionDispatch::Integration::Session.new(Rails.application)
        client.post "/mobile/session", params: {email_address: user.email_address, password: "correct-password", client_id: "android"}, as: :json
        abort "dormant route admitted request" unless client.response.status == 404 && Session.count == 0
        config = AddAuth.configuration
        config.mobile.lifetime = 30 * 86_400
        config.mobile.idle_timeout = 14 * 86_400
        config.mobile.clients = %w[android ios]
        config.mobile.enabled = true
        config.turbo_enabled = false
        client.get "/sign-in"
        abort "ordinary HTML missing" unless client.response.status == 200 && client.response.body.include?('name="password"')
        abort "Turbo unexpectedly loaded" if client.response.body.include?('/add_auth/turbo.js')
        client.post "/mobile/session", params: {email_address: user.email_address, password: "correct-password", client_id: "android"}, as: :json
        abort "mobile sign-in failed" unless client.response.status == 201
        token = client.response.parsed_body.fetch("token")
        abort "mobile created browser cookie" if client.response.headers["Set-Cookie"]
        abort "mobile accepted as cookie" if AddAuth::Rails::Runtime.sessions.resume(signed_value: token)
        headers = {"Authorization" => "Bearer " + token}
        client.get "/mobile/session", headers: headers
        abort "mobile resume failed" unless client.response.status == 200
        client.get "/mobile/session"
        abort "cookie-only API admitted" unless client.response.status == 401
        client.post "/session", params: {email_address: user.email_address, password: "correct-password"}
        abort "browser sign-in failed" unless client.response.status == 303
        client.get "/sessions"
        abort "mobile device absent from shared list" unless client.response.status == 200 && client.response.body.include?("Signed-in mobile device (android)")
        user.update!(password: "replacement-password")
        client.get "/mobile/session", headers: headers
        abort "reset failed to revoke mobile" unless client.response.status == 401
        abort "reset missed browser" if Session.where(revoked_at: nil).exists?
        puts "mobile package host verified"
      RUBY
    end
  end
end
