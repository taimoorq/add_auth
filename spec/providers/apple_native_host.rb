# frozen_string_literal: true

require "spec_helper"
require_relative "../support/isolated_host"

RSpec.describe "Native Apple in an installed-package host without OAuth middleware" do
  it "enrolls, independently confirms and authenticates with the optional JWT library" do
    Dir.mktmpdir("add-auth-native-apple-host-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: %w[jwt rspec-rails webmock capybara selenium-webdriver])
      host.run("generate", "authentication")
      host.run("generate", "add_auth:accounts")
      host.run("generate", "add_auth:external_identities")
      host.run("generate", "add_auth:mobile_sessions")
      host.run("generate", "migration", "AllowNativeAccounts")
      migration = Dir[File.join(host.root, "db/migrate/*_allow_native_accounts.rb")].fetch(0)
      File.write(migration, File.read(migration).sub("def change", "def change\n    change_column_null :users, :password_digest, true"))
      user_file = File.join(host.root, "app/models/user.rb")
      File.write(user_file, File.read(user_file).sub("has_secure_password", "has_secure_password validations: false"))
      host.configure
      File.write(File.join(host.root, "config/initializers/zz_native_fixture.rb"), <<~RUBY)
        require "add_auth/rails/provider_libraries/apple_native"
        AddAuth.configure do |config|
          config.lifecycle.enabled = true
          config.trusted_recovery_address = ->(user) { user.email_address if user.confirmed_at }
          provider = AddAuth::Core::ExternalIdentities::Configuration.new(id: "apple-ios", issuer: "https://appleid.apple.com",
            audience: "com.example.native", verifier: AddAuth::Rails::ProviderLibraries::AppleNative::Verifier.new)
          config.external_identities.register_native(configuration: provider)
          config.external_identities.enabled = true
          config.mobile.enabled = true
          config.mobile.lifetime = 30 * 86_400
          config.mobile.idle_timeout = 14 * 86_400
          config.mobile.clients = ["ios"]
          config.mobile.apple_providers = {"ios" => "apple-ios"}
        end
      RUBY
      host.run("db:migrate")
      if ENV["ADD_AUTH_EJECT_UI"] == "1"
        host.runner(<<~RUBY)
          require "add_auth/rails/ejection"
          ejection = AddAuth::Rails::Ejection.new(host_root: Rails.root)
          %i[views controllers javascript mailer_views].each { |kind| ejection.install(kind: kind) }
          abort "mobile controller was not ejected" unless File.file?(Rails.root.join("app/controllers/add_auth/mobile_sessions_controller.rb"))
        RUBY
      end
      output = host.runner("load #{File.expand_path("../support/native_apple_journey.rb", __dir__).inspect}", skip_executor: true)
      expect(output).to include("5 examples, 0 failures")
    end
  end
end
