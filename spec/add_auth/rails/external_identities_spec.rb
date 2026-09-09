# frozen_string_literal: true

require_relative "../../support/external_identity_host"
require "add_auth/rails/stores/authority"
require "add_auth/core/remaining_factors"
require "add_auth/core/passwords/credential"
require "add_auth/core/passwords/bcrypt_support"
require "add_auth/core/passwords/legacy_bcrypt"
require "webauthn/fake_client"

RSpec.describe AddAuth::Core::ExternalIdentities, database: true do
  let(:now) { Time.now.change(usec: 0) }
  let(:clock) { double(now: now) }
  let(:digest) { AddAuth.configuration.session_token_digest }
  let(:browser) { AddAuth::Core::BrowserBinding.new(digest: digest).generate }
  let!(:user) { User.create!(email_address: "owner@example.test", password: "correct-password") }
  let(:store) { AddAuth::Rails::Stores::ExternalIdentities.new(user_model: User, identity_model: AddAuthExternalIdentity, transaction_model: AddAuthExternalTransaction) }
  let(:session_store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  let(:eligible) { ->(account) { account.email_address != "disabled@example.test" } }
  let(:config) { described_class::Configuration.new(id: "provider-web", issuer: "https://identity.example.test", audience: "browser-client", verifier: verifier) }
  # A non-OmniAuth server verifier proves the optional protocol-independent port.
  # Only an object minted by this server fixture is accepted; request Hashes fail.
  let(:server_type) {
    Class.new {
      attr_reader :claims
      def initialize(claims) = @claims = claims
    }
  }
  let(:verifier) { ->(server_result:, transaction:) { server_result.claims if server_result.instance_of?(server_type) && transaction.configuration.equal?(config) } }
  let(:passwords_enabled) { true }
  let(:passkeys_enabled) { true }
  let(:email_enabled) { false }
  let(:recovery_address) { nil }
  let(:legacy_verifier) { nil }
  let(:current_password_support) { AddAuth::Core::Passwords::BcryptSupport.new }
  let(:access) do
    AddAuth::Core::AccessPolicy.new(credentials: ->(id) { AddAuthCredential.find_by(external_id: id) },
      passkeys_enabled: passkeys_enabled, email_enabled: email_enabled, password_enabled: passwords_enabled,
      trusted_recovery_address: ->(_) { recovery_address }, external_enabled: true,
      external_current: ->(**args) { service.credential_current?(**args) })
  end
  let(:sessions) { AddAuth::Core::Sessions.new(store: session_store, digest: digest, eligible: eligible, clock: clock, access_policy: access) }
  let(:policy) do
    AddAuth::Core::StepUp.new(clock: clock,
      purposes: {link_external_identity: {methods: [:password, :external_identity]}, unlink_external_identity: {methods: [:password, :external_identity]},
                 edit_account: {methods: [:external_identity]}, strict_action: {methods: [:external_identity, :passkey], require_passkey: true}},
      methods_available: ->(account) { access.methods_for(account) },
      credential_current: ->(user:, evidence:) { evidence.method == :password || service.credential_current?(user: user, id: evidence.credential_id, version: evidence.credential_version) })
  end
  let(:remaining) do
    AddAuth::Core::RemainingFactors.new(access_policy: access,
      passkey_count: ->(account) { AddAuthCredential.where(user_id: account.id, revoked_at: nil).count },
      password_available: ->(account) {
        AddAuth::Core::Passwords::Credential.new(legacy_verifier: legacy_verifier).available?(user: account, current: current_password_support)
      })
  end
  let(:revoke) { ->(user_id:, at:) { session_store.revoke_all_in_transaction(user_id: user_id, at: at) } }
  let(:authority) do
    AddAuth::Rails::Stores::Authority.new(user_model: User, session_model: Session,
      external_invalidator: ->(user_id:, at:) { described_class.invalidate_credentials_in_transaction(store: store, user_id: user_id, at: at) })
  end
  let(:service) { described_class.new(store: store, configurations: [config], sessions: sessions, access_policy: access, policy: policy, eligible: eligible, digest: digest, revoke_authority: revoke, remaining_method: remaining, enabled: true, clock: clock) }

  def transaction(purpose: :sign_in, account: nil, session: nil)
    service.begin_transaction(configuration_id: config.id, browser_secret: browser, user: account, session: session, purpose: purpose).credential
  end

  def evidence(pending, subject: "Subject-A", authenticated_at: nil, **claims)
    config.verify(server_result: server_type.new({issuer: config.issuer, audience: config.audience, subject: subject,
                                                  provenance: "server-fixture-v1", authenticated_at: authenticated_at}.merge(claims)), transaction: pending)
  end

  def grant(account, session, purpose)
    proof = AddAuth::Core::StepUp::Evidence.new(user_id: account.id, session_id: session.id, method: :password,
      verified_at: now, credential_version: account.password_digest, session_digest: session.token_digest)
    policy.authorize(user: account, session_id: session.id, purpose: purpose, evidence: proof).credential
  end

  def link(account = user, subject: "Subject-A")
    session = sessions.start(user: account, method: :password).session
    pending = transaction(purpose: :link_external_identity, account: account, session: session)
    service.link(user: account, session: session, evidence: evidence(pending, subject: subject), grant: grant(account, session, :link_external_identity))
  end

  def race(*operations)
    ready, start = Queue.new, Queue.new
    threads = operations.map do |operation|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          start.pop
          operation.call
        end
      end
    end
    operations.size.times { ready.pop }
    operations.size.times { start << true }
    threads.map(&:value)
  end

  it "uses generated schema and keeps provider setup dormant" do
    expect(AddAuth.configuration.external_identities.enabled).to be(false)
    expect(AddAuthExternalIdentity.column_names).not_to include("access_token", "refresh_token", "email", "profile")
    expect(ActiveRecord::Base.connection.indexes(:add_auth_external_identities).find { |index| index.columns == ["namespace"] }.unique).to be(true)
  end

  it "requires trusted verifier output and deeply freezes redacted evidence" do
    pending = transaction
    expect(config.verify(server_result: {subject: "forged"}, transaction: pending)).to be_nil
    expect { described_class::VerifiedIdentity.new }.to raise_error(NoMethodError)
    proof = evidence(pending)
    expect(proof).to be_frozen
    expect { proof.subject.replace("changed") }.to raise_error(FrozenError)
    expect { pending.id.replace("changed") }.to raise_error(FrozenError)
    expect(proof.inspect + pending.inspect + config.inspect).not_to include(proof.subject, pending.id, config.issuer)
    expect(evidence(pending, issuer: "https://wrong.example.test")).to be_nil
    expect(evidence(pending, audience: "other-client")).to be_nil
    expect(evidence(pending, subject: "")).to be_nil
  end

  it "correlates durable pending state to the browser and expiry and cancels once" do
    pending = transaction
    expect(service.pending(transaction: pending.id, browser_secret: "x" * 43)).to be_nil
    expect(service.pending(transaction: pending.id, browser_secret: browser).id).to eq(pending.id)
    expect(service.cancel(transaction: pending.id, browser_secret: browser)).to be(true)
    expect(service.cancel(transaction: pending.id, browser_secret: browser)).to be(false)
    pending = transaction
    allow(clock).to receive(:now).and_return(now + 300)
    expect(service.pending(transaction: pending.id, browser_secret: browser)).to be_nil
  end

  it "requires explicit binding and never searches or changes profile email" do
    proof = evidence(transaction)
    expect(service.sign_in(evidence: proof).reason).to eq(:identity_unbound)
    identity = link.credential
    user.update!(email_address: "changed@example.test")
    # Runtime lifecycle wiring now invalidates old provider transactions on an
    # address change. Start this new proof after that real committed event.
    allow(clock).to receive(:now).and_return(identity.reload.invalidated_at + 1)
    result = service.sign_in(evidence: evidence(transaction, email: "somebody-else@example.test"))
    expect(result).to be_success
    expect(result.user.id).to eq(user.id)
    expect(result.user.email_address).to eq("changed@example.test")
    expect(result.credential.id).to eq(identity.id)
    expect(result.session.authentication_external_version).to eq(identity.credential_version)
    expect(sessions.resume(signed_value: result.grant.bearer)).to be_present
  end

  it "allows exactly one callback to create a session on independent connections" do
    link
    proof = evidence(transaction)
    results = race(-> { service.sign_in(evidence: proof) }, -> { service.sign_in(evidence: proof) })
    expect(results.count(&:success?)).to eq(1)
    expect(results.reject(&:success?).map(&:reason)).to eq([:consumed_token])
    expect(Session.where(authenticated_with: "external_identity").count).to eq(1)
  end

  it "rolls transaction consumption back if session persistence fails" do
    link
    pending = transaction
    proof = evidence(pending)
    allow(sessions).to receive(:create_in_transaction).and_raise("simulated persistence failure")
    expect { service.sign_in(evidence: proof) }.to raise_error("simulated persistence failure")
    expect(service.pending(transaction: pending.id, browser_secret: browser)).to be_present
    allow(sessions).to receive(:create_in_transaction).and_call_original
    expect(service.sign_in(evidence: proof)).to be_success
  end

  it "denies stale expired evidence even after successful verification" do
    link
    proof = evidence(transaction)
    allow(clock).to receive(:now).and_return(now + 300)
    expect(service.sign_in(evidence: proof).reason).to eq(:expired_token)
  end

  it "never transfers a namespace when two accounts race to link it" do
    other = User.create!(email_address: "other@example.test", password: "correct-password")
    first_session = sessions.start(user: user, method: :password).session
    other_session = sessions.start(user: other, method: :password).session
    first = evidence(transaction(purpose: :link_external_identity, account: user, session: first_session))
    second = evidence(transaction(purpose: :link_external_identity, account: other, session: other_session))
    first_grant = grant(user, first_session, :link_external_identity)
    second_grant = grant(other, other_session, :link_external_identity)
    results = race(-> { service.link(user: user, session: first_session, evidence: first, grant: first_grant) },
      -> { service.link(user: other, session: other_session, evidence: second, grant: second_grant) })
    expect(results.count(&:success?)).to eq(1)
    expect(results.reject(&:success?).map(&:reason)).to eq([:identity_conflict])
    expect(AddAuthExternalIdentity.count).to eq(1)
  end

  it "preserves case-sensitive subjects and client namespaces" do
    expect(link(subject: "Subject-A")).to be_success
    expect(link(subject: "subject-a")).to be_success
    other_config = described_class::Configuration.new(id: "mobile", issuer: config.issuer, audience: "native", verifier: verifier)
    expect(other_config.namespace("Subject-A")).not_to eq(config.namespace("Subject-A"))
    expect(AddAuthExternalIdentity.count).to eq(2)
  end

  it "binds linking proof to the current user, session generation, purpose and policy" do
    session = sessions.start(user: user, method: :password).session
    pending = transaction(purpose: :link_external_identity, account: user, session: session)
    proof = evidence(pending)
    wrong = grant(user, session, :unlink_external_identity)
    expect(service.link(user: user, session: session, evidence: proof, grant: wrong).reason).to eq(:elevation_required)
    correct = grant(user, session, :link_external_identity)
    user.update!(add_auth_policy_version: 1)
    expect(service.link(user: user, session: session, evidence: proof, grant: correct).reason).to eq(:elevation_required)
    expect(AddAuthExternalIdentity.count).to eq(0)
  end

  it "denies current ineligible and strict accounts without interpreting the provider label as strong" do
    link
    user.update!(add_auth_strict: true)
    expect(service.sign_in(evidence: evidence(transaction))).to be_failure
    user.update!(add_auth_strict: false, email_address: "disabled@example.test")
    expect(service.sign_in(evidence: evidence(transaction))).to be_failure
    expect(sessions.start(user: user, method: :external_identity)).to be_nil
  end

  it "rejects callbacks after deletion" do
    link
    proof = evidence(transaction)
    user.destroy!
    expect(service.sign_in(evidence: proof).reason).to eq(:identity_unbound)
  end

  it "requires real authentication occurrence time in the exact reauthentication transaction" do
    identity = link.credential
    session = service.sign_in(evidence: evidence(transaction)).session
    pending = transaction(purpose: :edit_account, account: user, session: session)
    [nil, now - 1, now + 1].each do |time|
      expect(service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: time)).reason).to eq(:elevation_required)
    end
    result = service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now))
    expect(result).to be_success
    expect(result.credential.method).to eq(:external_identity)
    expect(result.credential.credential_version).to eq(identity.credential_version)
    expect(result.credential.valid_for?(user: user, user_id: user.id, session_id: session.id,
      session_digest: session.token_digest, purpose: :unlink_external_identity, now: now)).to be(false)
    expect(service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now)).reason).to eq(:consumed_token)
  end

  it "persists and rechecks provider elevation with version while denying strict passkey purposes" do
    link
    session = service.sign_in(evidence: evidence(transaction)).session
    pending = transaction(purpose: :strict_action, account: user, session: session)
    expect(service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now)).reason).to eq(:elevation_required)
    pending = transaction(purpose: :edit_account, account: user, session: session)
    elevated = service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now))
    rotated = sessions.rotate_for_step_up(user: user, session: session, grant: elevated.credential)
    expect(sessions.with_elevation(user: user, session: rotated.session, purpose: :edit_account, policy: policy)).to be_success
    AddAuthExternalIdentity.update_all(credential_version: "new-version")
    expect(sessions.resume(signed_value: rotated.bearer)).to be_nil
  end

  it "revokes all outstanding sessions atomically on unlink and prevents stale credentials resuming" do
    identity = link.credential
    provider_session = service.sign_in(evidence: evidence(transaction)).grant
    session = sessions.start(user: user, method: :password).session
    proof = grant(user, session, :unlink_external_identity)
    expect(service.unlink(user: user, session: session, identity_id: identity.id, grant: proof)).to be_success
    expect(identity.reload.revoked_at).to eq(now)
    expect(Session.where(revoked_at: nil).count).to eq(0)
    expect(sessions.resume(signed_value: provider_session.bearer)).to be_nil
    expect(service.sign_in(evidence: evidence(transaction)).reason).to eq(:identity_unbound)
  end

  it "rolls unlink back when shared authority invalidation fails" do
    identity = link.credential
    session = sessions.start(user: user, method: :password).session
    allow(revoke).to receive(:call).and_raise("invalidation failed")
    expect { service.unlink(user: user, session: session, identity_id: identity.id, grant: grant(user, session, :unlink_external_identity)) }.to raise_error("invalidation failed")
    expect(identity.reload.revoked_at).to be_nil
  end

  it "preserves one usable identity when provider-only removals race" do
    first = link.credential
    second = link(subject: "Subject-B").credential
    user.update_columns(password_digest: "")
    session = service.sign_in(evidence: evidence(transaction)).session
    pending = transaction(purpose: :unlink_external_identity, account: user, session: session)
    proof = service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now)).credential
    # The first unlink retires all sessions too; the second may fail at the
    # authority gate before reaching the last-method check. Both are safe.
    results = race(-> { service.unlink(user: user, session: session, identity_id: first.id, grant: proof) },
      -> { service.unlink(user: user, session: session, identity_id: second.id, grant: proof) })
    expect(results.count(&:success?)).to eq(1)
    expect(AddAuthExternalIdentity.where(revoked_at: nil).count).to eq(1)
    remaining = AddAuthExternalIdentity.find_by!(revoked_at: nil)
    session = service.sign_in(evidence: evidence(transaction, subject: remaining.subject)).session
    pending = transaction(purpose: :unlink_external_identity, account: user, session: session)
    proof = service.reauthenticate(user: user, session: session, evidence: evidence(pending, subject: remaining.subject, authenticated_at: now)).credential
    expect(service.unlink(user: user, session: session, identity_id: remaining.id, grant: proof).reason).to eq(:last_credential)
  end
  it "serializes account deletion and callback finalization without orphan authority" do
    link
    proof = evidence(transaction)
    race(-> { service.sign_in(evidence: proof) }, -> { store.with_user(id: user.id) { |account| account.destroy! } })
    expect(User.find_by(id: user.id)).to be_nil
    expect(AddAuthExternalIdentity.count).to eq(0)
    expect(Session.count).to eq(0)
  end

  it "serializes password enrollment against removing the last provider" do
    identity = link.credential
    user.update_columns(password_digest: "")
    session = service.sign_in(evidence: evidence(transaction)).session
    pending = transaction(purpose: :unlink_external_identity, account: user, session: session)
    proof = service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now)).credential
    results = race(-> { service.unlink(user: user, session: session, identity_id: identity.id, grant: proof) },
      -> { store.with_user(id: user.id) { |account| account.update!(password: "new-enrolled-password") } })
    expect(user.reload.authenticate("new-enrolled-password")).to be_truthy
    expect(results.first.success? || [:last_credential, :elevation_required].include?(results.first.reason)).to be(true)
    expect(access.fallback?(user)).to be(true)
  end

  it "never lets a pre-unlink callback revive after explicit relinking" do
    identity = link.credential
    proof = evidence(transaction)
    session = sessions.start(user: user, method: :password).session
    expect(service.unlink(user: user, session: session, identity_id: identity.id, grant: grant(user, session, :unlink_external_identity))).to be_success
    allow(clock).to receive(:now).and_return(now + 1)
    expect(link).to be_success
    expect(service.sign_in(evidence: proof).reason).to eq(:invalid_credentials)
  end
  def invalidate_account(at: now)
    store.with_user(id: user.id) do |_account|
      authority.revoke(user_id: user.id, at: at)
    end
  end

  it "preserves binding ownership while fencing anonymous pre-reset callbacks and old provider sessions" do
    identity = link.credential
    old_version, linked_at = identity.credential_version, identity.linked_at
    existing = service.sign_in(evidence: evidence(transaction)).grant
    pending = transaction
    expect(pending.user_id).to be_nil
    proof = evidence(pending)
    invalidate_account
    expect(service.sign_in(evidence: proof).reason).to eq(:invalid_credentials)
    expect(sessions.resume(signed_value: existing.bearer)).to be_nil
    expect(identity.reload.revoked_at).to be_nil
    expect(identity.linked_at).to eq(linked_at)
    expect(identity.credential_version).not_to eq(old_version)
    expect(identity.invalidated_at).to eq(now)
    allow(clock).to receive(:now).and_return(now + 1)
    expect(service.sign_in(evidence: evidence(transaction))).to be_success
  end

  it "serializes password reset against an already verified anonymous callback" do
    link
    proof = evidence(transaction)
    results = race(-> { service.sign_in(evidence: proof) }, -> {
      store.with_user(id: user.id) do |account|
        account.update!(password: "reset-during-provider-callback")
        authority.revoke(user_id: account.id, at: now)
      end
    })
    result = results.first
    expect(result.success? || result.reason == :invalid_credentials).to be(true)
    expect(sessions.resume(signed_value: result.grant.bearer)).to be_nil if result.success?
    expect(Session.where(revoked_at: nil).count).to eq(0)
    expect(service.sign_in(evidence: proof).reason).to eq(:invalid_credentials)
    allow(clock).to receive(:now).and_return(now + 1)
    expect(service.sign_in(evidence: evidence(transaction))).to be_success
  end

  it "keeps pre-disable callbacks invalid after re-enable" do
    link
    proof = evidence(transaction)
    store.with_user(id: user.id) do |account|
      account.update!(email_address: "disabled@example.test")
      authority.revoke(user_id: account.id, at: now)
    end
    store.with_user(id: user.id) { |account| account.update!(email_address: "owner@example.test") }
    expect(service.sign_in(evidence: proof).reason).to eq(:invalid_credentials)
    allow(clock).to receive(:now).and_return(now + 1)
    expect(service.sign_in(evidence: evidence(transaction))).to be_success
  end

  it "rolls binding invalidation back with the owning account transaction and never regresses its cutoff" do
    identity = link.credential
    previous_version = identity.credential_version
    expect do
      store.with_user(id: user.id) do |_account|
        authority.revoke(user_id: user.id, at: now)
        raise "reset failed"
      end
    end.to raise_error("reset failed")
    expect(identity.reload.invalidated_at).to be_nil
    expect(identity.credential_version).to eq(previous_version)
    invalidate_account(at: now + 2)
    version = identity.reload.credential_version
    invalidate_account(at: now)
    expect(identity.reload.invalidated_at).to eq(now + 2)
    expect(identity.credential_version).to eq(version)
    expect { service.invalidate_credentials_in_transaction(user_id: user.id, at: now) }.to raise_error(AddAuth::Error, /account transaction/)
  end

  context "with real remaining-factor policy" do
    def prepare_provider_only(digest: "", scheme: nil)
      identity = link.credential
      user.update_columns(password_digest: digest, add_auth_password_scheme: scheme)
      session = service.sign_in(evidence: evidence(transaction)).session
      pending = transaction(purpose: :unlink_external_identity, account: user, session: session)
      proof = service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now)).credential
      [identity, session, proof]
    end

    def remove_prepared(prepared)
      identity, session, proof = prepared
      service.unlink(user: user, session: session, identity_id: identity.id, grant: proof)
    end

    def stored_passkey(account: user, revoked_at: nil)
      response = WebAuthn::FakeClient.new("https://example.test").create(challenge: Base64.strict_encode64(SecureRandom.random_bytes(32)), user_verified: true)
      credential = WebAuthn::Credential.from_create(response)
      AddAuthCredential.create!(user: account, external_id: credential.id, public_key: credential.public_key, revoked_at: revoked_at)
    end

    it "denies zero credentials and malformed persisted password despite enabled methods" do
      prepared = prepare_provider_only(digest: "unsupported-password-format")
      expect(remove_prepared(prepared).reason).to eq(:last_credential)
      expect(prepared.first.reload.revoked_at).to be_nil
      expect(prepared[1].reload.revoked_at).to be_nil
    end

    it "ignores revoked and other-account passkeys" do
      prepared = prepare_provider_only
      stored_passkey(revoked_at: now)
      other = User.create!(email_address: "other-factor@example.test", password: "correct-password")
      stored_passkey(account: other)
      expect(remove_prepared(prepared).reason).to eq(:last_credential)
    end

    it "allows removal when an owned live passkey remains" do
      prepared = prepare_provider_only
      stored_passkey
      expect(remove_prepared(prepared)).to be_success
      expect(AddAuthCredential.where(user_id: user.id, revoked_at: nil).count).to eq(1)
    end

    context "when passkeys are disabled" do
      let(:passkeys_enabled) { false }
      it "does not count a live stored credential" do
        prepared = prepare_provider_only
        stored_passkey
        expect(remove_prepared(prepared).reason).to eq(:last_credential)
      end
    end

    ["", "unknown", "devise_bcrypt"].each do |scheme|
      it "rejects unsupported persisted #{scheme.inspect} password profile" do
        digest = BCrypt::Password.create("correct-password", cost: 4).to_s
        prepared = prepare_provider_only(digest: digest, scheme: scheme)
        expect(remove_prepared(prepared).reason).to eq(:last_credential)
      end
    end

    context "with legacy verifier configured" do
      let(:legacy_verifier) { AddAuth::Core::Passwords::LegacyBcrypt.new(maximum_cost: 4) }
      it "accepts supported persisted legacy credentials" do
        digest = BCrypt::Password.create("correct-password", cost: 4).to_s
        expect(remove_prepared(prepare_provider_only(digest: digest, scheme: "devise_bcrypt"))).to be_success
      end
      it "rejects cost above the current verifier support without hashing" do
        digest = BCrypt::Password.create("correct-password", cost: 4).to_s.sub("$04$", "$05$")
        prepared = prepare_provider_only(digest: digest, scheme: "devise_bcrypt")
        expect(BCrypt::Engine).not_to receive(:hash_secret)
        expect(remove_prepared(prepared).reason).to eq(:last_credential)
      end
    end

    context "with email enabled" do
      let(:email_enabled) { true }
      it "requires independent recovery trust" do
        expect(remove_prepared(prepare_provider_only).reason).to eq(:last_credential)
      end
      context "with a mismatched trusted address" do
        let(:recovery_address) { "old@example.test" }
        it("rejects unlink") { expect(remove_prepared(prepare_provider_only).reason).to eq(:last_credential) }
      end
      context "with the trusted current address" do
        let(:recovery_address) { user.email_address }
        it("allows unlink") { expect(remove_prepared(prepare_provider_only)).to be_success }
      end
    end

    context "with passwords disabled" do
      let(:passwords_enabled) { false }
      it "does not count a supported persisted digest" do
        # Provision the binding before changing feature configuration, then use
        # genuine provider reauthentication rather than a fabricated password grant.
        allow(access).to receive(:sign_in_allowed?).and_call_original
        allow(access).to receive(:sign_in_allowed?).with(user, :password).and_return(true)
        identity = link.credential
        allow(access).to receive(:sign_in_allowed?).and_call_original
        session = service.sign_in(evidence: evidence(transaction)).session
        pending = transaction(purpose: :unlink_external_identity, account: user, session: session)
        proof = service.reauthenticate(user: user, session: session, evidence: evidence(pending, authenticated_at: now)).credential
        expect(remove_prepared([identity, session, proof]).reason).to eq(:last_credential)
      end
    end
  end
end
