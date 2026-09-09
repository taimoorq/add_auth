# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require_relative "../support/devise_source_host"

RSpec.describe "Protected migration checkpoints" do
  it "repeats a committed interrupted batch, binds revisions, and stops on conflicts without losing the cursor" do
    Dir.mktmpdir("add-auth-checkpoint-") do |directory|
      profile = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? :uuid : :standard
      host = DeviseSourceHost.new(directory)
      host.prepare(profile: profile)
      host.run("generate", "add_auth:devise_accounts")
      host.run("db:migrate")
      output = host.runner(<<~RUBY)
        load #{File.expand_path("../../examples/devise_backfill.rb", __dir__).inspect}
        directory = Dir.mktmpdir("private-checkpoint-")
        path = File.join(directory, "checkpoint.json")
        manifest = {"owner" => "fixture", "environment" => "test", "database" => User.connection_db_config.database,
          "source_revision" => "source-fixture-v1", "config_revision" => "config-fixture-v1", "recovery_snapshot" => "synthetic-snapshot",
          "rollback_artifact" => "canonical-reader-bridge", "expected_accounts" => 3}
        options = {manifest: manifest, checkpoint: path, source_revision: "source-fixture-v1", config_revision: "config-fixture-v1", limit: 1}
        begin
          DeviseBackfillRehearsal.batch(**options, after_commit: -> { raise "simulated process death" })
          abort "fault was not injected"
        rescue RuntimeError => error
          raise unless error.message == "simulated process death"
        end
        abort "uncommitted cursor appeared" if File.exist?(path)
        first = DeviseBackfillRehearsal.batch(**options)
        abort "repeated batch was not idempotent" unless first["last_batch"][:unchanged] == 1
        before = File.binread(path)
        begin
          DeviseBackfillRehearsal.batch(**options.merge(config_revision: "other-config"))
          abort "wrong configuration resumed"
        rescue ArgumentError
        end
        users = User.order(:id).to_a
        original_email = users[1].email
        users[1].update_columns(email: users[0].email.upcase)
        begin
          DeviseBackfillRehearsal.batch(**options)
          abort "collision advanced checkpoint"
        rescue ArgumentError
        end
        abort "failed batch lost cursor" unless File.binread(path) == before
        users[1].update_columns(email: original_email)
        DeviseBackfillRehearsal.batch(**options)
        last = DeviseBackfillRehearsal.batch(**options)
        abort "resume failed" unless last["complete"] && User.where(add_auth_authority: "devise").count == 3
        abort "checkpoint exposed credentials" if File.read(path).include?("@") || File.read(path).include?("$2a$")
        abort "backfill sent mail" unless ActionMailer::Base.deliveries.empty?
        abort "source password changed" unless users[0].reload.valid_password?("source-password")
        puts "manifest/interruption/retry/conflict/source-authority verified"
      RUBY
      expect(output).to include("manifest/interruption/retry/conflict/source-authority verified")
    ensure
      host&.cleanup
    end
  end
end
