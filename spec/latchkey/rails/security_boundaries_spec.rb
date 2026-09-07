# frozen_string_literal: true

require "rails_helper"
require "rake"

RSpec.describe "Additional trust-boundary probes", database: true do
  let!(:user) { User.create!(email_address: "audit@example.test", password: "correct-password") }

  it "A18 rejects an existing session even without reloading its object" do
    existing = user.sessions.create!
    service = Latchkey::Rails::Runtime.email
    service.issue(identifier: user.email_address)
    raw = service.delivery_token(digest: LatchkeySignInToken.last.digest)
    expect { service.consume(token: raw) { existing } }.to raise_error(Latchkey::Error, /finalizer/)
  end

  it "A19 doctor detects missing expiry and revocation columns" do
    allow(Session).to receive(:column_names).and_return(Session.column_names - %w[expires_at last_seen_at revoked_at])
    Rails.application.load_tasks unless Rake::Task.task_defined?("latchkey:doctor")
    task = Rake::Task["latchkey:doctor"]
    task.reenable
    expect { task.invoke }.to raise_error(SystemExit)
  end

  it "A20 does not emit a challenge bypass when a closed policy denies access" do
    bypasses = []
    intake = Latchkey::Core::Intake.new(digest: Latchkey.configuration.sign_in_token_digest,
      normalizer: ->(x) { x }, limiter: ->(**_) { true },
      challenge: Latchkey::Core::Challenge::Test.new(mode: :unavailable), challenge_on: [:sign_in],
      challenge_when_unavailable: :closed, on_challenge_unavailable: ->(**args) { bypasses << args })
    expect(intake.call(identifier: user.email_address, ip: "192.0.2.1", action: :sign_in)).to eq(:challenge_unavailable)
    expect(bypasses).to be_empty
  end
end
