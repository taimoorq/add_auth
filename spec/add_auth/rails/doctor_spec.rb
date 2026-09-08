# frozen_string_literal: true

require "rails_helper"
require "rake"
require "add_auth/rails/doctor"
require_relative "../../support/passkey_runtime"
Rake::Task.define_task(:environment)
load File.expand_path("../../../lib/tasks/add_auth.rake", __dir__)

RSpec.describe "add_auth:doctor", type: :task, database: true do
  it "passes for the fully migrated dummy host" do
    task = Rake::Task["add_auth:doctor"]
    task.reenable

    expect { task.invoke }.to output(/AddAuth configuration checks passed/).to_stdout
  end
end

RSpec.describe "Passkey cleanup diagnostics", database: true do
  include_context "passkey runtime"
  let(:runtime) { AddAuth::Rails::Runtime }

  def cleanup_problem
    AddAuth::Rails::Doctor.new.call.grep(/successful cleanup/)
  end

  it "requires a recent completed sweep in production and notices a stalled schedule" do
    allow(Rails.env).to receive(:production?).and_return(true)
    now = Time.now
    allow(Time).to receive(:now).and_return(now)
    expect(cleanup_problem).not_to be_empty
    runtime.record_maintenance
    expect(cleanup_problem).to be_empty
    allow(Time).to receive(:now).and_return(now + 121)
    expect(cleanup_problem).not_to be_empty
  end

  it "does not require production scheduling in a local trial" do
    expect(cleanup_problem).to be_empty
  end

  it "does not accept another application's success in an unnamespaced shared cache" do
    config = AddAuth.configuration
    previous = config.sign_in_token_digest
    runtime.record_maintenance
    config.sign_in_token_digest = AddAuth::Core::Digest::Hmac.new(secret: "other-app" * 8, salt: "maintenance-test")
    expect(runtime.maintenance_current?).to be(false)
  ensure
    config.sign_in_token_digest = previous
  end

  it "rejects future, malformed and unavailable heartbeat receipts" do
    allow(Rails.env).to receive(:production?).and_return(true)
    cache = runtime.rate_limit_cache
    [Time.now.to_i + 60, "recent", nil].each do |receipt|
      allow(cache).to receive(:read).and_return(receipt)
      expect(cleanup_problem).not_to be_empty
    end
    allow(cache).to receive(:read).and_raise(IOError)
    expect(cleanup_problem).not_to be_empty
  end
end

RSpec.describe AddAuth::Rails::Doctor, database: true do
  subject(:problems) { described_class.new.call }

  it "checks every required session and email column" do
    {Session => described_class::SESSION_COLUMNS, AddAuthSignInToken => described_class::TOKEN_COLUMNS}.each do |model, columns|
      original = model.column_names
      columns.each do |column|
        allow(model).to receive(:column_names).and_return(original - [column])
        expect(described_class.new.call.join).to include("migrations")
      end
      allow(model).to receive(:column_names).and_return(original)
    end
  end

  it "detects lost unique indexes and lifecycle hooks" do
    allow(User.connection).to receive(:indexes).and_call_original
    allow(User.connection).to receive(:indexes).with(User.table_name).and_return([])
    allow(User).to receive(:<).with(AddAuth::Rails::UserLifecycle).and_return(false)
    expect(problems.join).to include("unique User.email_address", "UserLifecycle")
  end

  it "rejects a cache without atomic increment" do
    old = AddAuth.configuration.rate_limit_store
    AddAuth.configuration.rate_limit_store = ActiveSupport::Cache::NullStore.new
    expect(problems.join).to include("atomic rate-limit cache")
  ensure
    AddAuth.configuration.rate_limit_store = old
  end
  it "detects a host override that could remove hardened cookie attributes" do
    allow(ApplicationController).to receive(:instance_method).and_call_original
    allow(ApplicationController).to receive(:instance_method).with(:add_auth_write_cookie).and_return(double(owner: ApplicationController))
    expect(problems.join).to include("hardened cookie/session hook add_auth_write_cookie")
  end

  it "checks production mail, durable jobs and scheduling for standalone notifications" do
    config = AddAuth.configuration
    previous = [config.email_link.enabled, config.notifications.enabled, config.passkeys.enabled]
    config.email_link.enabled = false
    config.notifications.enabled = true
    config.passkeys.enabled = false
    allow(Rails.env).to receive(:production?).and_return(true)
    expect(problems.join).to include("durable job adapter", "production mail delivery", "successful cleanup")
    AddAuth::Rails::Runtime.record_maintenance
    expect(described_class.new.call.join).not_to include("successful cleanup")
  ensure
    config.email_link.enabled, config.notifications.enabled, config.passkeys.enabled = previous
  end

  it "reports invalid maintenance configuration before the scheduler runs" do
    options = AddAuth.configuration.maintenance
    previous = options.batch_size
    options.batch_size = 0
    expect(problems.join).to include("maintenance batch size")
  ensure
    options.batch_size = previous
  end

  it "keeps an installed stock password entry guarded even when password authentication is disabled" do
    config = AddAuth.configuration
    previous = config.passwords_enabled
    allow(SessionsController).to receive(:<).with(AddAuth::Rails::PasswordEntry).and_return(false)
    expect(described_class.new.call.join).to include("shared password entry")
    config.passwords_enabled = false
    expect(described_class.new.call.join).to include("shared password entry")
    config.passwords_enabled = "false"
    expect(described_class.new.call.join).to include("passwords_enabled to true or false")
  ensure
    config.passwords_enabled = previous
  end
end
