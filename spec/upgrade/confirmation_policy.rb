# frozen_string_literal: true

require "spec_helper"
require "rails"
require_relative "../support/isolated_host"

RSpec.describe "Confirmation policy with existing lifecycle storage" do
  it "keeps required confirmation usable without the new column, then upgrades additively" do
    Dir.mktmpdir("add-auth-confirmation-upgrade-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate")
      host.run("generate", "authentication")
      host.run("db:migrate")
      host.run("generate", "add_auth:accounts", "--no-email-link")
      receipt = Dir[File.join(host.root, "db/migrate/*_add_add_auth_provisioning.rb")].fetch(0)
      FileUtils.mv(receipt, File.join(directory, "new-provisioning-migration.rb"))
      host.run("db:migrate")
      host.configure
      File.open(File.join(host.root, "config/initializers/add_auth.rb"), "a") do |file|
        file.puts "AddAuth.configuration.lifecycle.enabled = true"
      end
      result = host.runner(<<~SOURCE)
        require "add_auth/rails/doctor"
        abort "fixture unexpectedly has the new column" if User.column_names.include?("add_auth_provisioned_at")
        abort "existing required host failed doctor" unless AddAuth::Rails::Doctor.new.call.empty?
        runtime = AddAuth::Rails::Runtime
        result = runtime.accounts.register(identifier: "existing@example.test", password: "existing-password")
        abort "required registration changed" unless result.success? && result.grant.nil?
        user = User.find_by!(email_address: "existing@example.test")
        abort "confirmation fabricated" if user.confirmed_at
        record = AddAuthAccountToken.find_by!(user_id: user.id, purpose: "confirm")
        delivery = runtime.accounts.claim_delivery(digest: record.digest)
        abort "confirmation delivery unavailable (Rails \#{Rails.version}, JSON \#{JSON::VERSION})" unless delivery
        token = delivery.fetch(:token)
        abort "old schema could not confirm" unless runtime.accounts.consume(token: token, purpose: :confirm).success?
        abort "old confirmed account cannot sign in" unless runtime.sessions.start(user: user.reload, method: :password)
        AddAuth.configuration.lifecycle.confirmation_required = false
        begin
          runtime.accounts
          abort "optional profile accepted missing migration"
        rescue AddAuth::Error => error
          abort "missing migration recovery unclear" unless error.message.include?("migrate")
        end
        puts "existing required storage verified"
      SOURCE
      expect(result).to include("existing required storage verified")
      host.run("generate", "add_auth:accounts", "--no-email-link")
      host.run("db:migrate")
      result = host.runner(<<~SOURCE)
        previous = User.find_by!(email_address: "existing@example.test")
        abort "migration invented a provisioning receipt" if previous.add_auth_provisioned_at
        abort "migration erased confirmed evidence" unless previous.confirmed_at
        AddAuth.configuration.lifecycle.confirmation_required = false
        runtime = AddAuth::Rails::Runtime
        result = runtime.accounts.register(identifier: "new@example.test", password: "new-account-password")
        abort "upgraded optional registration failed" unless result.success? && result.grant
        abort "verification fabricated" if result.user.confirmed_at
        abort "provisioning receipt missing" unless result.user.add_auth_provisioned_at
        abort "old account denied after additive upgrade" unless runtime.sessions.start(user: previous, method: :password)
        puts "additive confirmation upgrade verified"
      SOURCE
      expect(result).to include("additive confirmation upgrade verified")
    end
  end
end
