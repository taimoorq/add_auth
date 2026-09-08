# frozen_string_literal: true

require "rails_helper"
require "add_auth/rails/doctor"

RSpec.describe "Rate-limit store compatibility", type: :request, database: true do
  let!(:user) { User.create!(email_address: "counter@example.test", password: "correct-password") }

  around do |example|
    previous = AddAuth.configuration.rate_limit_store
    example.run
  ensure
    AddAuth.configuration.rate_limit_store = previous
  end

  before do
    # Normal suite has no optional Solid Cache dependency. The real adapter and
    # its missing-row race are exercised in operations/solid_cache_contract.rb.
    stub_const("SolidCache", Module.new)
    stub_const("SolidCache::Store", Class.new(ActiveSupport::Cache::MemoryStore))
  end

  ["configured", "Rails default", "subclass"].each do |source|
    it "rejects #{source} Solid Cache before admitting a password or enqueuing email" do
      cache = ((source == "subclass") ? Class.new(SolidCache::Store) : SolidCache::Store).new
      if source == "Rails default"
        AddAuth.configuration.rate_limit_store = nil
        allow(Rails).to receive(:cache).and_return(cache)
      else
        AddAuth.configuration.rate_limit_store = cache
      end
      expect(cache).not_to receive(:increment)
      expect(AddAuth::Rails::Doctor.new.call.join).to include("Solid Cache", "separate atomic store")
      ["/sign-in/password", "/sign-in/email", "/session"].each do |path|
        post path, params: {email_address: user.email_address, password: "correct-password"}
        expect(response).to have_http_status(:service_unavailable)
      end
      expect(Session.count).to eq(0)
      expect(AddAuthSignInToken.count).to eq(0)
      expect(ActiveJob::Base.queue_adapter.enqueued_jobs).to be_empty
    end
  end

  it "permits a separate counter store while Rails uses Solid Cache" do
    allow(Rails).to receive(:cache).and_return(SolidCache::Store.new)
    expect(AddAuth::Rails::Doctor.new.call.join).not_to include("Solid Cache", "atomic rate-limit cache")
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to have_http_status(:see_other)
    expect(Session.count).to eq(1)
  end
end
