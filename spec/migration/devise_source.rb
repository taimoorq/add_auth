# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require "json"
require_relative "../support/devise_source_host"

RSpec.describe "Devise source preflight" do
  profiles = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? [:uuid] : %i[standard aligned peppered custom]
  profiles.each do |profile|
    it "inspects the populated #{profile} source without changing accounts or emitting credentials" do
      Dir.mktmpdir("add-auth-devise-") do |directory|
        host = DeviseSourceHost.new(directory)
        host.prepare(profile: profile)
        result = host.runner(<<~RUBY)
          require "json"
          require "digest"
          require "add_auth/rails/migration/effective_inventory"
          # Compare all rows before/after privately; report no account values.
          before = Digest::SHA256.hexdigest(User.unscoped.order(:id).pluck(*User.column_names).inspect)
          report = AddAuth::Rails::Migration::EffectiveInventory.new.call
          after = Digest::SHA256.hexdigest(User.unscoped.order(:id).pluck(*User.column_names).inspect)
          abort "preflight mutated source" unless before == after
          abort "unexpected mail" unless ActionMailer::Base.deliveries.empty?
          puts JSON.generate(report)
        RUBY
        report = JSON.parse(result.lines.last)
        account = report.dig("facts", "accounts").first
        expect(report.dig("facts", "versions", "devise")).to eq("5.0.4")
        expect(report.dig("facts", "complete")).to be(true)
        expect(account.dig("counts", "inspected")).to eq(3)
        expect(account.dig("counts", "unconfirmed")).to eq(1)
        expect(account.dig("counts", "locked")).to eq(1)
        expect(account["pepper_configured"]).to eq(profile == :peppered)
        expect(account["custom_verifier"]).to eq(%i[aligned custom].include?(profile))
        expect(account["primary_key_type"]).to eq((profile == :uuid) ? "uuid" : "integer")
        expect(result).not_to include("source-password", "synthetic-secret-pepper", "@example.test", "$2a$", "$2b$")
        expect(report["migration_ready"]).to be(false)
        task = host.run("add_auth:devise_preflight")
        # Task JSON is pretty printed; parsed below.
        expect(JSON.parse(task).fetch("status")).to eq("inventory")

        bounded = host.runner(<<~RUBY)
          require "json"
          require "add_auth/rails/migration/effective_inventory"
          puts JSON.generate(AddAuth::Rails::Migration::EffectiveInventory.new(limit: 1).call)
        RUBY
        expect(JSON.parse(bounded.lines.last).dig("facts", "complete")).to be(false)
        write_guard = host.runner(<<~RUBY)
          require "add_auth/rails/migration/effective_inventory"
          old_keys = User.authentication_keys
          User.define_singleton_method(:authentication_keys) do
            User.update_all(email: "MUST-NOT-WRITE@example.test")
            old_keys
          end
          begin
            AddAuth::Rails::Migration::EffectiveInventory.new.call
            abort "write guard did not reject mutation"
          rescue ActiveRecord::StatementInvalid
            abort "source was changed" if User.where(email: "MUST-NOT-WRITE@example.test").exists?
            User.where(id: User.first.id).update_all(failed_attempts: 0)
            puts "write guard and connection recovery verified"
          end
        RUBY
        expect(write_guard).to include("write guard and connection recovery verified")
      ensure
        host&.cleanup
      end
    end
  end
end
