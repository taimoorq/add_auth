# frozen_string_literal: true

require_relative "../../support/external_identity_host"
require "add_auth/core/mobile_handoffs"
require "add_auth/rails/stores/mobile_handoffs"
require "add_auth/rails/stores/maintenance"

RSpec.describe AddAuth::Core::MobileHandoffs, database: true do
  let(:now) { Time.now.change(usec: 0) }
  let(:clock) { double(now: now) }
  let!(:user) { User.create!(email_address: "handoff@example.test", password: "correct-password") }
  let(:digest) { AddAuth.configuration.sign_in_token_digest }
  let(:browser) { SecureRandom.urlsafe_base64(32) }
  let(:state) { SecureRandom.urlsafe_base64(32) }
  let(:verifier) { SecureRandom.urlsafe_base64(48) }
  let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }
  let(:callback) { "com.example.app://auth/callback" }
  let(:profile) { AddAuth::Core::MobileProfile.new(lifetime: 30 * 86_400, idle_timeout: 14 * 86_400, clients: %w[android ios], callbacks: {"android" => callback, "ios" => callback}) }
  let(:store) { AddAuth::Rails::Stores::MobileHandoffs.new(user_model: User, handoff_model: AddAuthMobileHandoff, session_model: Session) }
  let(:external_store) { AddAuth::Rails::Stores::ExternalIdentities.new(user_model: User, identity_model: AddAuthExternalIdentity, transaction_model: AddAuthExternalTransaction) }
  let(:session_store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  let(:eligible) { ->(account) { account.email_address != "denied@example.test" } }
  let(:server_type) { Struct.new(:subject) }
  let(:provider) do
    AddAuth::Core::ExternalIdentities::Configuration.new(id: "provider", issuer: "https://provider.example.test", audience: "application",
      clock: clock, verifier: ->(server_result:, transaction:) {
        if server_result.instance_of?(server_type) && transaction.configuration.equal?(provider)
          {issuer: provider.issuer, audience: provider.audience, subject: server_result.subject, provenance: "trusted-test-library"}
        end
      })
  end
  let(:access) do
    AddAuth::Core::AccessPolicy.new(credentials: ->(_) {}, passkeys_enabled: false, email_enabled: false,
      trusted_recovery_address: ->(_) {}, external_enabled: true, external_current: ->(**args) { external.credential_current?(**args) })
  end
  let(:sessions) { AddAuth::Core::Sessions.new(store: session_store, digest: digest, eligible: eligible, clock: clock, access_policy: access, mobile_profile: profile) }
  let(:external) do
    AddAuth::Core::ExternalIdentities.new(store: external_store, configurations: [provider], sessions: sessions, access_policy: access,
      policy: AddAuth::Core::StepUp.new(purposes: {}), eligible: eligible, digest: digest, revoke_authority: ->(**_) {}, remaining_method: ->(_) { true },
      clock: clock, enabled: true, mobile_enabled: true)
  end
  let!(:identity) do
    AddAuthExternalIdentity.create!(user: user, namespace: provider.namespace("Subject"), provider_id: provider.id, issuer: provider.issuer,
      audience: provider.audience, subject: "Subject", provenance: "trusted-test-library", credential_version: "current-version", linked_at: now - 1)
  end
  subject(:handoffs) { described_class.new(store: store, profile: profile, sessions: sessions, access_policy: access, digest: digest, clock: clock) }

  def pending(purpose = :mobile_sign_in)
    external.begin_transaction(configuration_id: provider.id, browser_secret: browser, purpose: purpose).credential
  end

  def begin_handoff(transaction = pending, **arguments)
    result = handoffs.begin_transaction(pending: transaction, client_id: "android", callback: callback, state: state,
      code_challenge: challenge, code_challenge_method: "S256", **arguments)
    [transaction, result]
  end

  def evidence(transaction)
    provider.verify(server_result: server_type.new("Subject"), transaction: transaction)
  end

  def issue
    transaction, result = begin_handoff
    expect(result).to be_success
    proof = evidence(transaction)
    result = external.mobile_handoff(evidence: proof, handoffs: handoffs)
    expect(result).to be_success
    result.credential
  end

  def exchange(code, **arguments)
    handoffs.exchange(code: code, state: state, code_verifier: verifier, client_id: "android", **arguments)
  end

  it "binds initiation to exact registered callback, strong state and S256 verifier" do
    [{callback: "https://attacker.example/callback"}, {client_id: "other"}, {code_challenge_method: "plain"},
      {state: "short"}, {code_challenge: "short"}, {state: {}}, {callback: callback + "?next=x"}].each do |attributes|
      expect(begin_handoff(pending, **attributes).last).to be_failure
    end
    expect(begin_handoff(pending(:sign_in)).last).to be_failure
    expect(AddAuthMobileHandoff.count).to eq(0)
  end

  it "makes a mobile callback incapable of creating a browser Session" do
    transaction, result = begin_handoff
    expect(result).to be_success
    proof = evidence(transaction)
    expect(external.sign_in(evidence: proof)).to be_failure
    handoff = external.mobile_handoff(evidence: proof, handoffs: handoffs).credential
    expect(Session.count).to eq(0)
    expect(handoff.code).to match(described_class::CODE)
    expect(handoff).to have_attributes(callback: callback, state: state)
    expect(handoff.inspect).not_to include(handoff.code, state)
    expect(external.mobile_handoff(evidence: proof, handoffs: handoffs).reason).to eq(:consumed_token)
    expect(AddAuthMobileHandoff.first.digest).to eq(digest.digest(handoff.code))
    expect(AddAuthMobileHandoff.first.inspect).not_to include(state)
  end

  it "does not burn the code on wrong proof or client and permits one correct exchange" do
    handoff = issue
    [{state: "z" * 43}, {code_verifier: "z" * 43}, {client_id: "ios"}, {code_verifier: nil}].each do |arguments|
      expect(exchange(handoff.code, **arguments)).to be_failure
      expect(AddAuthMobileHandoff.first.consumed_at).to be_nil
      expect(Session.count).to eq(0)
    end
    result = exchange(handoff.code)
    expect(result).to be_success
    expect(result.session).to have_attributes(user_id: user.id, transport: "mobile", authentication_external_id: identity.id.to_s)
    expect(result.grant.bearer).to match(AddAuth::Core::MobileProfile::PATTERN)
    expect(sessions.resume(signed_value: result.grant.bearer)).to be_nil
    expect(sessions.resume_mobile(bearer: result.grant.bearer)).to be_present
    expect(exchange(handoff.code).reason).to eq(:consumed_token)
    expect(Session.count).to eq(1)
  end

  it "expires at the exact deadline and never treats the code as an API credential" do
    handoff = issue
    expect(sessions.resume_mobile(bearer: handoff.code)).to be_nil
    allow(clock).to receive(:now).and_return(now + 60)
    expect(exchange(handoff.code).reason).to eq(:expired_token)
    expect(Session.count).to eq(0)
  end

  it "rechecks account policy and identity version after issuance" do
    handoff = issue
    user.update_column(:add_auth_strict, true)
    expect(exchange(handoff.code)).to be_failure
    user.update_column(:add_auth_strict, false)
    identity.update!(credential_version: "changed")
    expect(exchange(handoff.code)).to be_failure
    expect(Session.count).to eq(0)
  end

  it "rechecks current host eligibility without consuming a denied account's code" do
    handoff = issue
    user.update_column(:email_address, "denied@example.test")
    expect(exchange(handoff.code)).to be_failure
    expect(Session.count).to eq(0)
    expect(AddAuthMobileHandoff.first.consumed_at).to be_nil
  end

  it "invalidates issued codes through existing reset authority even when mobile is disabled" do
    handoff = issue
    user.update!(password: "replacement-password")
    expect(AddAuthMobileHandoff.first.consumed_at).to be_present
    expect(exchange(handoff.code)).to be_failure
    expect(Session.count).to eq(0)
  end

  it "does not issue from an unbound, retired or pre-reset provider transaction" do
    transaction, = begin_handoff
    identity.update!(revoked_at: now)
    expect(external.mobile_handoff(evidence: evidence(transaction), handoffs: handoffs)).to be_failure
    identity.update!(revoked_at: nil)
    user.update!(password: "replacement-password")
    expect(external.mobile_handoff(evidence: evidence(transaction), handoffs: handoffs)).to be_failure
    expect(AddAuthMobileHandoff.first.digest).to be_nil
  end

  it "commits only one winner on concurrent correct exchanges using separate connections" do
    handoff = issue
    results = race(-> { exchange(handoff.code) }, -> { exchange(handoff.code) })
    expect(results.count(&:success?)).to eq(1)
    expect(Session.count).to eq(1)
    expect(results.find(&:failure?).reason).to eq(:consumed_token)
  end

  it "rolls back the credential when consume fails after Session creation" do
    handoff = issue
    allow(store).to receive(:consume).and_return(false)
    expect { exchange(handoff.code) }.to raise_error(AddAuth::Error)
    expect(Session.count).to eq(0)
    expect(AddAuthMobileHandoff.first.consumed_at).to be_nil
  end

  it "bounds expired handoff cleanup and retains live rows" do
    issue
    3.times { begin_handoff }
    AddAuthMobileHandoff.update_all(expires_at: now)
    begin_handoff
    cleanup = AddAuth::Rails::Stores::Maintenance.new(model: AddAuthMobileHandoff, kind: :mobile_handoff)
    expect(cleanup.purge_expired(before: now, now: now, limit: 2)).to eq(2)
    expect(AddAuthMobileHandoff.count).to eq(3)
    expect(cleanup.purge_expired(before: now, now: now, limit: 2)).to eq(2)
    expect(AddAuthMobileHandoff.count).to eq(1)
  end

  def race(*operations)
    ready, go = Queue.new, Queue.new
    threads = operations.map do |operation|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          operation.call
        end
      end
    end
    operations.length.times { ready.pop }
    operations.length.times { go << true }
    threads.map(&:value)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end
end
