# frozen_string_literal: true

require "spec_helper"
require_relative "../support/isolated_host"
require "socket"

RSpec.describe "Google sign-in in an installed-package Rails host" do
  it "preserves identity, remembered sessions and independent enrollment in all browser modes" do
    Dir.mktmpdir("add-auth-google-host-") do |directory|
      host = IsolatedHost.new(directory)
      port = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }
      host.environment["GOOGLE_FIXTURE_PORT"] = port.to_s
      host.environment["MOBILE_CALLBACK_PORT"] = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }.to_s
      host.environment["ADD_AUTH_FIXTURE_TLS"] = "1"
      host.install(IsolatedHost.candidate(directory), label: "candidate",
        extra_gems: %w[omniauth-google-oauth2 omniauth-rails_csrf_protection rspec-rails capybara selenium-webdriver webmock webrick])
      host.run("generate", "authentication")
      host.run("generate", "add_auth:accounts")
      host.run("generate", "add_auth:external_identities")
      host.run("generate", "add_auth:mobile_sessions")
      host.run("generate", "migration", "AllowProviderOnlyAccounts")
      migration = Dir[File.join(host.root, "db/migrate/*_allow_provider_only_accounts.rb")].fetch(0)
      File.write(migration, File.read(migration).sub("def change", "def change\n    change_column_null :users, :password_digest, true"))
      host.configure
      user_file = File.join(host.root, "app/models/user.rb")
      File.write(user_file, File.read(user_file).sub("has_secure_password", "has_secure_password validations: false"))
      File.write(File.join(host.root, "app/controllers/fixture_home_controller.rb"), <<~RUBY)
        class FixtureHomeController < ApplicationController
          def index = render plain: "Signed in as \#{Current.user.email_address}"
        end
      RUBY
      routes = File.join(host.root, "config/routes.rb")
      File.write(routes, File.read(routes).sub("Rails.application.routes.draw do", "Rails.application.routes.draw do\n  root to: 'fixture_home#index'"))
      File.write(File.join(host.root, "config/initializers/zz_google_fixture.rb"), <<~RUBY)
        require "add_auth/rails/provider_libraries/omniauth"
        require "add_auth/rails/provider_libraries/omniauth_correlation"
        Rails.application.config.middleware.use AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation, providers: ["google_oauth2"]
        Rails.application.config.middleware.use OmniAuth::Builder do
          provider :google_oauth2, "google-browser-fixture", "synthetic-secret", client_options: {
            site: "http://127.0.0.1:\#{ENV.fetch('GOOGLE_FIXTURE_PORT')}", authorize_url: "/authorize", token_url: "/token"
          }
        end
        verifier = AddAuth::Rails::ProviderLibraries::OmniAuth::Verifier.new(provider: "google_oauth2", provenance: "omniauth-google-oauth2")
        AddAuth.configure do |config|
          config.lifecycle.enabled = true
          config.trusted_recovery_address = ->(user) { user.email_address if user.confirmed_at }
          config.external_identities.register(id: "google", label: "Google", middleware_name: "google_oauth2",
            configuration: AddAuth::Core::ExternalIdentities::Configuration.new(id: "google", issuer: "https://accounts.google.com",
              audience: "google-browser-fixture", verifier: verifier))
          config.external_identities.enabled = true
          config.mobile.enabled = true
          config.mobile.lifetime = 30 * 86_400
          config.mobile.idle_timeout = 14 * 86_400
          config.mobile.clients = %w[android ios]
          config.mobile.callbacks = {"android" => "https://localhost:\#{ENV.fetch('MOBILE_CALLBACK_PORT')}/callback"}
        end
      RUBY
      host.run("db:migrate")
      if ENV["ADD_AUTH_EJECT_UI"] == "1"
        host.runner(<<~RUBY)
          require "add_auth/rails/ejection"
          ejection = AddAuth::Rails::Ejection.new(host_root: Rails.root)
          %i[views controllers javascript mailer_views].each { |kind| ejection.install(kind: kind) }
          %w[provider_sign_ins/_prepare.html.erb provider_sign_ins/_enrollment.html.erb external_identities/_index.html.erb].each do |path|
            abort "provider view was not ejected" unless File.file?(Rails.root.join("app/views/add_auth", path))
          end
        RUBY
      end
      output = host.runner("load #{File.expand_path("../support/google_provider_journey.rb", __dir__).inspect}", skip_executor: true)
      expect(output).to include("9 examples, 0 failures")
    end
  end
end
