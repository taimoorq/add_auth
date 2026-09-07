# frozen_string_literal: true

require "webauthn/fake_client"

RSpec.shared_examples "passkey store contract" do
  let(:digest) { Latchkey::Core::Digest::Hmac.new(secret: "s" * 32, salt: "passkey-contract") }
  let(:access) { Latchkey::Core::AccessPolicy.new(credentials: ->(id) { store.credential(id: id) }, passkeys_enabled: true, email_enabled: false, trusted_recovery_address: ->(_) {}) }
  let(:sessions) { Latchkey::Core::Sessions.new(store: session_store, digest: digest, eligible: ->(_) { true }, access_policy: access) }
  let(:policy) do
    Latchkey::Core::StepUp.new(purposes: {manage_passkeys: {methods: [:password, :passkey]}},
      credential_current: ->(user:, evidence:) { evidence.method == :password || access.credential_current?(user: user, id: evidence.credential_id) })
  end
  let(:service) do
    Latchkey::Core::Strategies::Passkey.new(store: store, sessions: sessions, policy: policy, access_policy: access,
      digest: digest, eligible: ->(_) { true }, rp_id: "example.test", origins: ["https://example.test"], name: "Test", notify: ->(**) {}, limiter: limiter)
  end
  let(:limiter) { ->(**) { true } }
  let(:secret) { Latchkey::Core::BrowserBinding.new(digest: digest).generate }
  let(:client) { WebAuthn::FakeClient.new("https://example.test", encoding: :base64url) }

  def prepare
    initial = sessions.start(user: user, method: :password)
    proof = sessions.reauthenticate(user: user, session: initial.session, purpose: :manage_passkeys, policy: policy) { |account| account }
    sessions.rotate_for_step_up(user: user, session: initial.session, grant: proof.credential).session
  end

  it "uses the same real cryptographic registration/assertion contract over this store" do
    session = prepare
    start = service.registration_options(user: user, session: session, browser_secret: secret).credential
    expect(start[:publicKey][:authenticatorSelection]).to include(residentKey: "required", userVerification: "required")
    response = client.create(challenge: start[:publicKey][:challenge], user_verified: true)
    registered = service.register(transaction: start[:transaction], credential_response: response, user: user, session: session, browser_secret: secret)
    expect(registered).to be_success
    login = service.authentication_options(browser_secret: secret).credential
    assertion = client.get(challenge: login[:publicKey][:challenge], user_verified: true, backup_state: false,
      user_handle: Base64.urlsafe_decode64(start[:publicKey][:user][:id]))
    first = service.authenticate(transaction: login[:transaction], credential_response: assertion, browser_secret: secret)
    expect(first).to be_success
    expect(sessions.resume(signed_value: first.credential.bearer)).to be_present
    expect(service.authenticate(transaction: login[:transaction], credential_response: assertion, browser_secret: secret)).not_to be_success
  end

  it "does not store a credential when browser UV is missing or the initiating bearer changed" do
    session = prepare
    start = service.registration_options(user: user, session: session, browser_secret: secret).credential
    response = client.create(challenge: start[:publicKey][:challenge], user_verified: false)
    expect(service.register(transaction: start[:transaction], credential_response: response, user: user, session: session, browser_secret: secret)).not_to be_success
    expect(store.credentials(user: user)).to be_empty
    sessions.revoke(session: session)
    response = client.create(challenge: start[:publicKey][:challenge], user_verified: true)
    expect(service.register(transaction: start[:transaction], credential_response: response, user: user, session: session, browser_secret: secret)).not_to be_success
    expect(store.credentials(user: user)).to be_empty
  end

  it "denies anonymous creation before persistence when its shared budget is exhausted" do
    expect(limiter).to receive(:call).with(key: digest.digest("passkey:anonymous-ceremonies"), limit: 1000).and_return(false)
    expect(store).not_to receive(:create_ceremony)
    expect(service.authentication_options(browser_secret: secret).reason).to eq(:rate_limited)
  end

  it "allows only the originating browser to cancel its ceremony" do
    start = service.authentication_options(browser_secret: secret).credential
    expect(service.cancel(transaction: start[:transaction], browser_secret: "x" * 43)).to be(false)
    expect(service.cancel(transaction: start[:transaction], browser_secret: secret)).to be(true)
  end
end
