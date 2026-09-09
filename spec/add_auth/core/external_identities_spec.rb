# frozen_string_literal: true

require "spec_helper"
require_relative "../../support/memory_external_transactions"

RSpec.describe AddAuth::Core::ExternalIdentities do
  let(:now) { Time.utc(2026, 9, 8, 12) }
  let(:clock) { double(now: now) }
  let(:digest) { AddAuth::Core::Digest::Hmac.new(salt: "external-test", secret: "x" * 32) }
  let(:browser) { AddAuth::Core::BrowserBinding.new(digest: digest).generate }
  let(:store) { MemoryExternalTransactions.new }
  let(:config) { described_class::Configuration.new(id: "web", issuer: "https://issuer.test", audience: "client", verifier: ->(**_) {}) }
  let(:service) { build(enabled: true) }

  def build(**options)
    described_class.new(store: store, configurations: [config], sessions: nil, access_policy: nil, policy: nil,
      eligible: ->(_) { true }, digest: digest, revoke_authority: ->(**_) {}, remaining_method: ->(_) { false }, clock: clock, **options)
  end

  it "is disabled unless explicitly composed and rejects arbitrary proof hashes" do
    expect(build.begin_transaction(configuration_id: "web", browser_secret: browser).reason).to eq(:disabled)
    expect(build.sign_in(evidence: {}).reason).to eq(:disabled)
    expect(service.sign_in(evidence: {}).reason).to eq(:invalid_credentials)
    expect(service.reauthenticate(user: nil, session: nil, evidence: {}).reason).to eq(:elevation_required)
    expect(store.rows).to be_empty
  end

  it "stores digests of transaction and browser secrets with exact context and no tokens" do
    pending = service.begin_transaction(configuration_id: "web", browser_secret: browser).credential
    row = store.rows.values.fetch(0)
    expect(row.digest).to eq(digest.digest(pending.id))
    expect(row.browser_digest).to eq(digest.digest(browser))
    expect(row.to_h.values).not_to include(pending.id, browser)
    expect(row.purpose).to eq("sign_in")
    expect(row.user_id).to be_nil
    expect(row.issued_at).to eq(now)
    expect(row.expires_at).to eq(now + 300)
  end

  it "rejects unconfigured, malformed and account-bound anonymous requests" do
    expect(service.begin_transaction(configuration_id: "unknown", browser_secret: browser).reason).to eq(:invalid_credentials)
    expect(service.begin_transaction(configuration_id: "web", browser_secret: {}).reason).to eq(:invalid_credentials)
    expect(service.begin_transaction(configuration_id: "web", browser_secret: browser, user: Object.new).reason).to eq(:invalid_credentials)
    expect(service.pending(transaction: {}, browser_secret: browser)).to be_nil
    expect(store.rows).to be_empty
  end

  it "rejects durable configuration changes, future issuance, expiry and cancellation replay" do
    pending = service.begin_transaction(configuration_id: "web", browser_secret: browser).credential
    row = store.rows.values.fetch(0)
    row.audience = "other-client"
    expect(service.pending(transaction: pending.id, browser_secret: browser)).to be_nil
    row.audience = config.audience
    row.issued_at = now + 1
    expect(service.pending(transaction: pending.id, browser_secret: browser)).to be_nil
    row.issued_at = now
    expect(service.cancel(transaction: pending.id, browser_secret: browser)).to be(true)
    expect(service.cancel(transaction: pending.id, browser_secret: browser)).to be(false)
  end

  it "keeps namespaces unambiguous and configuration values immutable" do
    expect(config.namespace("Subject")).not_to eq(config.namespace("subject"))
    expect { config.id << "changed" }.to raise_error(FrozenError)
    expect { build(configurations: [config, config]) }.to raise_error(ArgumentError)
    expect { build(lifetime: 0) }.to raise_error(ArgumentError)
    expect { described_class::Configuration.new(id: "web", issuer: "", audience: "client", verifier: nil) }.to raise_error(ArgumentError)
  end
end
