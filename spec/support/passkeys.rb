# frozen_string_literal: true

require "webauthn/fake_client"
require "add_auth/rails/stores/passkeys"
require_relative "reauthentication"

RSpec.shared_context "passkey services" do
  include_context "public reauthentication"
  around do |example|
    options = AddAuth.configuration.passkeys
    previous = options.enabled
    options.enabled = true
    AddAuth.configuration.step_up.purposes[:manage_passkeys] = {methods: [:password, :email_link, :passkey], return_to: "/passkeys"}
    AddAuth.configuration.step_up.purposes[:manage_policy] = {methods: [:passkey], require_passkey: true, return_to: "/passkeys"}
    example.run
  ensure
    options.enabled = previous
  end

  let!(:user) { User.create!(email_address: "passkey@example.test", password: "correct-password") }
  let(:runtime) { AddAuth::Rails::Runtime }
  let(:browser_secret) { runtime.browser_binding.generate }
  let(:initial) { runtime.sessions.start(user: user, method: :password) }
  let(:events) { [] }
  let(:store) { AddAuth::Rails::Stores::Passkeys.new(user_model: User, session_model: Session, credential_model: AddAuthCredential, ceremony_model: AddAuthCeremony, token_model: AddAuthSignInToken) }
  let(:service) do
    AddAuth::Core::Strategies::Passkey.new(store: store, sessions: runtime.sessions, policy: runtime.step_up_policy,
      access_policy: runtime.access_policy, digest: AddAuth.configuration.sign_in_token_digest,
      eligible: AddAuth.configuration.eligible, rp_id: "example.test", origins: ["https://example.test"], name: "Test",
      notify: ->(**event) { events << event }, support_url: "/support", limiter: runtime.method(:limit))
  end
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:client) { WebAuthn::FakeClient.new("https://example.test", authenticator: authenticator, encoding: :base64url) }

  def password_elevation
    runtime.elevate_password(user: user, session: initial.session, purpose: :manage_passkeys,
      password: "correct-password", ip: "127.0.0.1", challenge_token: nil).credential
  end

  def registration(session: password_elevation.session, **overrides)
    options = service.registration_options(user: user, session: session, browser_secret: browser_secret)
    expect(options).to be_success
    response = client.create(challenge: options.credential.fetch(:publicKey).fetch(:challenge), user_verified: true, **overrides)
    [options.credential.fetch(:transaction), response, session]
  end

  def enroll
    transaction, response, session = registration
    result = service.register(transaction: transaction, credential_response: response, user: user,
      session: session, browser_secret: browser_secret)
    expect(result).to be_success
    [result.credential, session]
  end

  def assertion(session: nil, purpose: nil, **overrides)
    options = service.authentication_options(browser_secret: browser_secret, user: session && user, session: session, purpose: purpose)
    expect(options).to be_success
    response = client.get(challenge: options.credential.fetch(:publicKey).fetch(:challenge),
      user_verified: true, user_handle: Base64.urlsafe_decode64(user.reload.webauthn_id), backup_state: false, **overrides)
    [options.credential.fetch(:transaction), response]
  end

  def authenticate(transaction, response, **options)
    service.authenticate(transaction: transaction, credential_response: response, browser_secret: browser_secret, **options)
  end
end
