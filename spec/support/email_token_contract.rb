# frozen_string_literal: true

RSpec.shared_examples "email token lifecycle" do
  let(:digest) { Latchkey::Core::Digest::Hmac.new(salt: "email-test", secret: "s" * 32) }
  let(:clock) { double("clock", now: Time.now.utc) }
  let(:same_browser) { false }
  let(:service) do
    Latchkey::Core::Strategies::EmailLink.new(store: store, digest: digest,
      delivery_cipher: cipher, eligible: ->(account) { account.email_address != "disabled@example.test" },
      normalize_identifier: ->(identifier) { identifier.strip.downcase },
      identifier_for: ->(account) { account.email_address }, clock: clock, same_browser: same_browser)
  end

  def issue_link
    service.issue(identifier: "  PERSON@example.test ")
    rows.last
  end

  def consume_link(token, &block)
    service.consume(token: token, &block || ->(_account, persist) { persist.call })
  end

  context "with optional browser binding" do
    let(:same_browser) { true }
    let(:binding) { Latchkey::Core::BrowserBinding.new(digest: digest) }
    let(:secret) { binding.generate }

    it "requires the original secret without spending a link on a failed attempt" do
      service.issue(identifier: user.email_address, browser_digest: binding.digest(secret))
      record = rows.last
      raw = service.delivery_token(digest: record.digest)
      expect(record.browser_digest).not_to eq(secret)
      [nil, [], {}, "", "é" * 43, "x" * 10_000, binding.generate].each do |wrong|
        expect(service.preview(token: raw, browser_secret: wrong).fetch(:browser_matches)).to be(false)
        expect(service.consume(token: raw, browser_secret: wrong) { |_account, persist| persist.call }).not_to be_success
      end
      expect(service.preview(token: raw, browser_secret: secret).fetch(:browser_matches)).to be(true)
      expect(service.consume(token: raw, browser_secret: secret) { |_account, persist| persist.call }).to be_success
      expect(consume_link(raw)).not_to be_success
      expect(sessions.size).to eq(1)
    end

    it "does not issue a link from an older unbound intake job" do
      service.issue(identifier: user.email_address)
      expect(rows).to be_empty
    end
  end

  it "keeps issued links bound even when the option is disabled" do
    binding = Latchkey::Core::BrowserBinding.new(digest: digest)
    secret = binding.generate
    service.issue(identifier: user.email_address, browser_digest: binding.digest(secret))
    raw = service.delivery_token(digest: rows.last.digest)
    expect(consume_link(raw)).not_to be_success
    expect(service.consume(token: raw, browser_secret: secret) { |_account, persist| persist.call }).to be_success
  end

  it "rejects outstanding unbound links when browser binding is enabled" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    bound = Latchkey::Core::Strategies::EmailLink.new(store: store, digest: digest,
      delivery_cipher: cipher, eligible: ->(_) { true }, normalize_identifier: ->(value) { value },
      identifier_for: ->(account) { account.email_address }, same_browser: true)
    expect(bound.consume(token: raw, browser_secret: Latchkey::Core::BrowserBinding.new(digest: digest).generate) { |_account, persist| persist.call }).not_to be_success
    expect(sessions).to be_empty
  end

  it "delivers a real token from a protected intent and consumes it only once" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect(raw).to match(/\A[A-Za-z0-9_-]{43}\z/)
    expect(record.delivery_payload).not_to include(raw)
    expect(record.digest).to eq(digest.digest(raw))
    expect(service.delivery_token(digest: record.digest)).to eq(raw)
    result = consume_link(raw)
    expect(result).to be_success
    expect(result.session.user_id).to eq(user.id)
    expect(consume_link(raw).reason).to eq(:consumed_token)
    expect(service.delivery_token(digest: record.digest)).to be_nil
    expect(sessions.size).to eq(1)
  end

  it "replaces pending tokens and does not resurrect them on delivery failure" do
    first = issue_link
    raw = service.delivery_token(digest: first.digest)
    second = issue_link
    service.delivery_failed(digest: first.digest)
    expect(consume_link(raw).reason).to eq(:revoked_token)
    expect(service.delivery_token(digest: second.digest)).to be_a(String)
    service.delivery_failed(digest: second.digest)
    expect(service.delivery_token(digest: second.digest)).to be_nil
  end

  it "rejects at the exact expiry boundary, including delivery" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    allow(clock).to receive(:now).and_return(record.expires_at)
    expect(consume_link(raw).reason).to eq(:expired_token)
    expect(service.delivery_token(digest: record.digest)).to be_nil
    expect(sessions).to be_empty
  end

  it "rechecks account eligibility after issuance" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    disable_user
    expect(consume_link(raw).reason).to eq(:disabled)
    expect(service.delivery_token(digest: record.digest)).to be_nil
    expect(sessions).to be_empty
  end

  it "does not issue for unknown or ineligible accounts" do
    expect(service.issue(identifier: "unknown@example.test")).to be_nil
    disable_user
    expect(service.issue(identifier: "disabled@example.test")).to be_nil
    expect(rows).to be_empty
  end

  it "rejects wrong-purpose tokens and malformed client input" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    change_purpose(record)
    expect(consume_link(raw).reason).to eq(:invalid_credentials)
    [nil, [], {}, "", "x" * 10_000, "é" * 43].each do |token|
      expect(consume_link(token).reason).to eq(:invalid_credentials)
    end
    expect(sessions).to be_empty
  end

  it "requires a finalizer instead of burning a link without session persistence" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect { service.consume(token: raw) }.to raise_error(ArgumentError, /finalizer/)
    expect(consume_link(raw)).to be_success
  end

  it "cancels only the leased issuance, scrubs its bearer and never reports it delivered" do
    record = issue_link
    claim = service.claim_delivery(digest: record.digest)
    expect(service.finish_delivery(digest: record.digest, lease: claim.fetch(:lease), outcome: :cancelled)).to be(true)
    current = rows.find { |item| item.digest == record.digest }
    expect(current.revoked_at).not_to be_nil
    expect(current.delivered_at).to be_nil
    expect(current.delivery_payload).to be_nil
    expect(current.delivery_lease_key).to be_nil
    expect(consume_link(claim.fetch(:token)).reason).to eq(:revoked_token)
    expect(service.claim_delivery(digest: record.digest)).to be_nil
  end

  it "ignores cancellation from an old worker after its lease has been replaced" do
    record = issue_link
    old_claim = service.claim_delivery(digest: record.digest)
    service.delivery_retry(digest: record.digest, lease: old_claim.fetch(:lease))
    current_claim = service.claim_delivery(digest: record.digest)
    expect(service.finish_delivery(digest: record.digest, lease: old_claim.fetch(:lease), outcome: :cancelled)).to be(false)
    expect(service.finish_delivery(digest: record.digest, lease: current_claim.fetch(:lease), outcome: :delivered)).to be(true)
    current = rows.find { |item| item.digest == record.digest }
    expect(current.revoked_at).to be_nil
    expect(current.delivered_at).not_to be_nil
    expect(current.delivery_payload).to be_nil
  end

  it "rejects unrecognized delivery outcomes without modifying the intent" do
    record = issue_link
    claim = service.claim_delivery(digest: record.digest)
    expect { service.finish_delivery(digest: record.digest, lease: claim.fetch(:lease), outcome: :unknown) }.to raise_error(ArgumentError)
    expect(service.delivery_token(digest: record.digest)).to eq(claim.fetch(:token))
  end

  it "does not complete an unclaimed intent with a missing lease" do
    record = issue_link
    expect(service.finish_delivery(digest: record.digest, lease: nil, outcome: :cancelled)).to be(false)
    expect(service.delivery_token(digest: record.digest)).to be_a(String)
  end
end

RSpec.shared_examples "address-bound email proof" do
  it "revokes proof and delivery authority when the account address changes" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    change_address
    expect(consume_link(raw).reason).to eq(:revoked_token)
    expect(service.delivery_token(digest: record.digest)).to be_nil
    expect(sessions).to be_empty
  end
end
