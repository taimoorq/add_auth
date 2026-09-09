# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/native_authentication"
require "add_auth/core/mobile_profile"
require_relative "../../support/memory_external_transactions"

RSpec.describe AddAuth::Core::NativeAuthentication do
  let(:clock) { Struct.new(:now).new(Time.utc(2026, 9, 8, 12)) }
  let(:store) { MemoryExternalTransactions.new }
  let(:digest) { AddAuth::Core::Digest::Hmac.new(salt: "native-unit", secret: "s" * 32) }
  let(:server_result) { Object.new }
  let(:provider) do
    AddAuth::Core::ExternalIdentities::Configuration.new(id: "apple", issuer: "https://appleid.apple.com", audience: "native", clock: clock,
      verifier: ->(server_result:, transaction:) {
        {issuer: transaction.configuration.issuer, audience: "native", subject: "subject", provenance: "test-library"} if server_result.equal?(self.server_result)
      })
  end
  let(:profile) { AddAuth::Core::MobileProfile.new(lifetime: 30 * 86_400, idle_timeout: 14 * 86_400, clients: %w[ios android]) }
  let(:intake) { double(anonymous: true) }
  let(:verifier) { double(call: server_result) }
  let(:accounts) { double(register_external: AddAuth::Result.success(user: nil, strategy: :register)) }
  let(:external) do
    AddAuth::Core::ExternalIdentities.new(store: store, configurations: [provider], sessions: nil, access_policy: nil, policy: nil,
      eligible: ->(_) { true }, digest: digest, revoke_authority: ->(**_) {}, remaining_method: ->(_) { false },
      clock: clock, enabled: true, mobile_enabled: true)
  end
  subject(:service) do
    described_class.new(external_identities: external, profile: profile, providers: {"ios" => provider, "android" => provider},
      intake: intake, verify: verifier, accounts: -> { accounts })
  end

  def start(**args) = service.start(client_id: "ios", ip: "127.0.0.1", **args)

  def complete(proof, **args)
    service.complete(client_id: "ios", challenge_id: proof.id, nonce: proof.nonce, identity_token: "library-token", ip: "127.0.0.1", **args)
  end

  before do
    allow(external).to receive(:native_sign_in).and_return(AddAuth::Result.failure(reason: :identity_unbound))
  end

  it "stores only digests and delegates identity/session decisions using typed evidence" do
    proof = start.credential
    expect(proof.nonce).to match(/\A[A-Za-z0-9_-]{43}\z/)
    expect(proof.expires_at).to eq(clock.now + 300)
    expect(store.rows.values.first.to_h.values).not_to include(proof.id, proof.nonce)
    expect(proof.inspect).not_to include(proof.id, proof.nonce)
    expect(complete(proof, user_agent: "x" * 513).reason).to eq(:identity_unbound)
    expect(external).to have_received(:native_sign_in).with(evidence: an_instance_of(AddAuth::Core::ExternalIdentities::VerifiedIdentity),
      client_id: "ios", ip_address: "127.0.0.1", user_agent: nil)
  end

  it "preserves each limiter/challenge result before creating or verifying a transaction" do
    proof = start.credential
    %i[rate_limited challenge_rejected challenge_unavailable].each do |reason|
      allow(intake).to receive(:anonymous).and_return(reason)
      expect(start.reason).to eq(reason)
      expect(complete(proof).reason).to eq(reason)
    end
    expect(store.rows.size).to eq(1)
    expect(verifier).not_to have_received(:call)
  end

  it "rejects unknown clients, wrong client/nonce/id and malformed input before verification" do
    proof = start.credential
    expect(start(client_id: "unknown")).to be_failure
    expect(start(intent: "automatic-sign-up")).to be_failure
    [{client_id: "android"}, {client_id: "unknown"}, {nonce: "x" * 43}, {challenge_id: "x" * 43},
      {nonce: {}}, {identity_token: {}}, {identity_token: "x" * 16_385}, {identity_token: "\xff".b}].each do |arguments|
      expect(complete(proof, **arguments).reason).to eq(:invalid_credentials)
    end
    expect(verifier).not_to have_received(:call)
    expect(store.rows.values.first.consumed_at).to be_nil
  end

  it "requires a live unconsumed challenge even when the provider could verify a token" do
    proof = start.credential
    clock.now = proof.expires_at
    expect(complete(proof)).to be_failure
    clock.now -= 1
    expect(external.cancel(transaction: proof.id, browser_secret: proof.nonce, binding_context: "native:ios")).to be(true)
    expect(complete(proof)).to be_failure
    expect(verifier).not_to have_received(:call)
  end

  it "rejects untrusted library output without forwarding an identity or burning the challenge" do
    proof = start.credential
    allow(verifier).to receive(:call).and_return({sub: "forged"})
    expect(complete(proof)).to be_failure
    expect(external).not_to have_received(:native_sign_in)
    expect(store.rows.values.first.consumed_at).to be_nil
  end

  it "keeps enrollment and sign-in purposes separate while using the existing registration command" do
    sign_in = start.credential
    enrollment = start(intent: "enroll").credential
    expect(complete(enrollment)).to be_failure
    arguments = {client_id: "ios", identity_token: "library-token", ip: "127.0.0.1", identifier: "reader@example.test", profile: {name: "Reader"}}
    expect(service.enroll(**arguments, challenge_id: sign_in.id, nonce: sign_in.nonce)).to be_failure
    expect(accounts).not_to have_received(:register_external)
    expect(service.enroll(**arguments, challenge_id: enrollment.id, nonce: enrollment.nonce)).to be_success
    expect(accounts).to have_received(:register_external).with(identifier: "reader@example.test", profile: {name: "Reader"},
      evidence: have_attributes(purpose: AddAuth::Core::ExternalIdentities::NATIVE_ENROLL))
    expect(external).not_to have_received(:native_sign_in)
  end

  it "requires registered typed configurations and explicit enrollment composition" do
    expect { described_class.new(external_identities: external, profile: profile, providers: {"other" => provider}, intake: intake, verify: verifier) }.to raise_error(ArgumentError)
    sign_in_only = described_class.new(external_identities: external, profile: profile, providers: {"ios" => provider}, intake: intake, verify: verifier)
    expect(sign_in_only.start(client_id: "ios", ip: "127.0.0.1", intent: "enroll")).to be_failure
    expect(store.rows).to be_empty
  end
end
