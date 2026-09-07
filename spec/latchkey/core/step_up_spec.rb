# frozen_string_literal: true

require "spec_helper"

RSpec.describe Latchkey::Core::StepUp do
  Account = Struct.new(:id, :password_digest) unless defined?(Account)
  let(:user) { Account.new(7, "password-version") }
  let(:now) { Time.utc(2026, 9, 6, 12) }
  let(:clock) { double(now: now) }
  let(:service) do
    described_class.new(clock: clock, credential_current: ->(**) { true }, purposes: {
      manage_profile: {methods: %i[password email_link]},
      manage_passkeys: {methods: [:passkey], require_passkey: true}
    })
  end

  def evidence(method:, user_id: user.id, session_id: 42, verified_at: now - 60,
    user_verification: false, credential_id: nil)
    described_class::Evidence.new(user_id:, session_id:, method:, verified_at:,
      user_verification:, credential_id:, session_digest: "generation-1", credential_version: user.password_digest)
  end

  it "returns a purpose/session-bound grant for recent allowed evidence" do
    result = service.authorize(user: user, session_id: 42, purpose: :manage_profile,
      evidence: evidence(method: :password))
    expect(result).to be_success
    grant = result.credential
    expect(grant.valid_for?(user_id: 7, session_id: 42, user: user, session_digest: "generation-1", purpose: :manage_profile, now: now + 539)).to be(true)
    expect(grant.valid_for?(user_id: 7, session_id: 42, user: user, session_digest: "generation-1", purpose: :manage_passkeys, now: now + 1)).to be(false)
    expect(grant.inspect).not_to include("credential")
  end

  it "keeps freshness separate from method strength and requires UV for passkeys" do
    expect(service.authorize(user: user, session_id: 42, purpose: :manage_passkeys,
      evidence: evidence(method: :passkey, user_verification: false))).to be_failure
    result = service.authorize(user: user, session_id: 42, purpose: :manage_passkeys,
      evidence: evidence(method: :passkey, user_verification: true, credential_id: "cred-1"))
    expect(result).to be_success
    expect(result.credential.method).to eq(:passkey)
    expect(result.credential.user_verification).to be(true)
    allow(clock).to receive(:now).and_return(now + 301)
    expect(service.authorize(user: user, session_id: 42, purpose: :manage_passkeys,
      evidence: evidence(method: :passkey, user_verification: true))).to be_failure
  end

  it "fails generically for stale, mismatched, unknown or disallowed evidence" do
    cases = [
      evidence(method: :password, verified_at: now - 601),
      evidence(method: :password, user_id: 8),
      evidence(method: :password, session_id: 99),
      evidence(method: :passkey),
      evidence(method: :password)
    ]
    results = cases.map do |proof|
      purpose = (proof.method == :passkey) ? :manage_profile : :manage_passkeys
      service.authorize(user: user, session_id: 42, purpose:, evidence: proof)
    end
    results << service.authorize(user: user, session_id: 42, purpose: :unknown, evidence: evidence(method: :password))
    expect(results).to all(be_failure)
    expect(results.map(&:reason).uniq).to eq([:elevation_required])
  end

  it "rejects future evidence and invalid window configuration" do
    expect(service.authorize(user: user, session_id: 42, purpose: :manage_profile,
      evidence: evidence(method: :password, verified_at: now + 1))).to be_failure
    expect { described_class.new(purposes: {}, fresh_for: 0) }.to raise_error(ArgumentError)
    expect { described_class.new(purposes: {}, fresh_for: 1, strong_for: 2) }.to raise_error(ArgumentError)
  end

  it "returns a safe fallback for absent purposes without authorizing them" do
    policy = described_class.new(purposes: {profile: {methods: [:password], return_to: "/profile"}})
    expect(policy.return_to(:profile)).to eq("/profile")
    [nil, :removed, "https://untrusted.test", []].each do |purpose|
      expect(policy.return_to(purpose)).to eq("/")
      expect(policy.rule_for(purpose)).to be_nil
    end
  end
end

RSpec.describe "Current credential policy" do
  let(:user) { Struct.new(:id, :password_digest).new(1, "version") }
  let(:now) { Time.now }
  let(:proof) do
    Latchkey::Core::StepUp::Evidence.new(user_id: 1, session_id: 2, method: :passkey,
      verified_at: now, credential_id: "credential-1", session_digest: "bearer-1", user_verification: true)
  end

  it "requires a current credential verifier and reevaluates it when a grant is spent" do
    current = true
    policy = Latchkey::Core::StepUp.new(purposes: {manage_keys: {methods: [:passkey], require_passkey: true}},
      credential_current: ->(user:, evidence:) { current && user.id == 1 && evidence.credential_id == "credential-1" })
    grant = policy.authorize(user: user, session_id: 2, purpose: :manage_keys, evidence: proof).credential
    args = {user: user, user_id: 1, session_id: 2, session_digest: "bearer-1", purpose: :manage_keys, now: now + 1}
    expect(grant.valid_for?(**args)).to be(true)
    current = false
    expect(grant.valid_for?(**args)).to be(false)
    expect(grant.valid_for?(**args.merge(session_digest: "bearer-2"))).to be(false)
    default = Latchkey::Core::StepUp.new(purposes: {manage_keys: {methods: [:passkey]}})
    expect(default.authorize(user: user, session_id: 2, purpose: :manage_keys, evidence: proof)).to be_failure
  end
end
