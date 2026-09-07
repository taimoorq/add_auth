# frozen_string_literal: true

require "rails_helper"
require "rake"
require "latchkey/rails/doctor"
Rake::Task.define_task(:environment)
load File.expand_path("../../../lib/tasks/latchkey.rake", __dir__)

RSpec.describe "latchkey:doctor", type: :task, database: true do
  it "passes for the fully migrated dummy host" do
    task = Rake::Task["latchkey:doctor"]
    task.reenable

    expect { task.invoke }.to output(/session\/email\/challenge checks passed/).to_stdout
  end
end

RSpec.describe Latchkey::Rails::Doctor, database: true do
  subject(:problems) { described_class.new.call }

  it "checks every required session and email column" do
    {Session => described_class::SESSION_COLUMNS, LatchkeySignInToken => described_class::TOKEN_COLUMNS}.each do |model, columns|
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
    allow(User).to receive(:<).with(Latchkey::Rails::UserLifecycle).and_return(false)
    expect(problems.join).to include("unique User.email_address", "UserLifecycle")
  end

  it "rejects a cache without atomic increment" do
    old = Latchkey.configuration.rate_limit_store
    Latchkey.configuration.rate_limit_store = ActiveSupport::Cache::NullStore.new
    expect(problems.join).to include("atomic rate-limit cache")
  ensure
    Latchkey.configuration.rate_limit_store = old
  end
  it "detects a host override that could remove hardened cookie attributes" do
    allow(ApplicationController).to receive(:instance_method).and_call_original
    allow(ApplicationController).to receive(:instance_method).with(:latchkey_write_cookie).and_return(double(owner: ApplicationController))
    expect(problems.join).to include("hardened cookie/session hook latchkey_write_cookie")
  end
end
