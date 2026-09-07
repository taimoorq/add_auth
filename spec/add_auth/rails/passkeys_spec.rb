# frozen_string_literal: true

require "rails_helper"
require "timeout"
require_relative "../../support/passkeys"

RSpec.describe "Passkey ceremonies and account policy", database: true do
  include_context "passkey services"

  it "enrolls with fresh account proof and signs in discoverably using verified ownership" do
    credential, = enroll
    expect(credential.public_key).to be_present
    expect(user.reload.webauthn_id).not_to eq(user.id.to_s)
    transaction, response = assertion
    result = authenticate(transaction, response)
    expect(result).to be_success
    expect(result.session).to have_attributes(authenticated_with: "passkey", authentication_uv: true,
      authentication_credential_id: credential.external_id)
    expect(runtime.sessions.resume(signed_value: result.credential.bearer)).to be_present
    expect(credential.reload.last_used_at).to be_present
    expect(authenticate(transaction, response)).not_to be_success
    expect(events.map { |event| event[:kind] }).to include(:passkey_added)
  end

  it "does not begin enrollment from an ordinary unelevated session" do
    result = service.registration_options(user: user, session: initial.session, browser_secret: browser_secret)
    expect(result.reason).to eq(:elevation_required)
    expect(AddAuthCeremony.count).to eq(0)
  end

  it "requires UV during both registration and assertion and never trusts a method label" do
    transaction, response, session = registration(user_verified: false)
    expect(service.register(transaction: transaction, credential_response: response, user: user, session: session, browser_secret: browser_secret)).not_to be_success
    expect(AddAuthCredential.count).to eq(0)
    # The failed registration created a separate authenticator credential; pick
    # only the successfully enrolled credential for the following assertion.
    options = service.registration_options(user: user, session: session, browser_secret: browser_secret)
    response = client.create(challenge: options.credential[:publicKey][:challenge], user_verified: true)
    result = service.register(transaction: options.credential[:transaction], credential_response: response, user: user, session: session, browser_secret: browser_secret)
    expect(result).to be_success
    transaction, assertion = assertion(user_verified: false, allow_credentials: [result.credential.external_id])
    expect(authenticate(transaction, assertion)).not_to be_success
    expect(runtime.sessions.start(user: user, method: :passkey)).to be_nil
  end

  it "rejects wrong origin, challenge, signature, browser, RP and user handle" do
    credential, = enroll
    [
      ->(response) { response["response"]["signature"] = Base64.urlsafe_encode64("wrong", padding: false) },
      ->(response) { response["response"]["userHandle"] = Base64.urlsafe_encode64("wrong-owner", padding: false) },
      ->(response) {
        data = JSON.parse(Base64.urlsafe_decode64(response["response"]["clientDataJSON"]))
        data["origin"] = "https://evil.example"
        response["response"]["clientDataJSON"] = Base64.urlsafe_encode64(JSON.generate(data), padding: false)
      }
    ].each do |mutate|
      transaction, response = assertion
      mutate.call(response)
      expect(authenticate(transaction, response)).not_to be_success
    end
    authenticator.send(:credentials)["wrong.example"] = authenticator.send(:credentials).fetch("example.test")
    transaction, response = assertion(rp_id: "wrong.example")
    expect(authenticate(transaction, response)).not_to be_success
    transaction, response = assertion
    expect(service.authenticate(transaction: transaction, credential_response: response, browser_secret: runtime.browser_binding.generate)).not_to be_success
    replacement, = assertion
    expect(authenticate(replacement, response)).not_to be_success
    expect(credential.reload.last_used_at).to be_nil
  end

  it "accepts zero/zero and increasing counters but rejects equal, lower and nonzero-to-zero values" do
    credential, = enroll
    transaction, response = assertion(sign_count: 0)
    expect(authenticate(transaction, response)).to be_success
    transaction, response = assertion(sign_count: 10)
    expect(authenticate(transaction, response)).to be_success
    [10, 9, 0].each do |counter|
      transaction, response = assertion(sign_count: counter)
      expect(authenticate(transaction, response).reason).to eq(:counter_regression)
    end
    expect(credential.reload.sign_count).to eq(10)
  end

  it "rejects invalid or changed backup eligibility and permits backup-state changes for eligible keys" do
    _credential, = enroll
    transaction, response = assertion(backup_state: true, backup_eligibility: false)
    expect(authenticate(transaction, response)).not_to be_success
    transaction, response = assertion(backup_state: true, backup_eligibility: true)
    expect(authenticate(transaction, response)).not_to be_success
  end

  it "tracks backup-state changes for an eligible credential without treating them as stronger proof" do
    transaction, response, session = registration(backup_eligibility: true, backup_state: false)
    added = service.register(transaction: transaction, credential_response: response, user: user, session: session, browser_secret: browser_secret)
    expect(added).to be_success
    [true, false].each do |state|
      transaction, response = assertion(backup_eligibility: true, backup_state: state)
      expect(authenticate(transaction, response)).to be_success
      expect(added.credential.reload.backup_state).to eq(state)
    end
  end

  it "does not use an anonymous assertion as a bound reauthentication ceremony" do
    _credential, session = enroll
    transaction, response = assertion
    expect(authenticate(transaction, response, session: session)).not_to be_success
    expect(AddAuthCeremony.last.consumed_at).to be_nil
    expect(authenticate(transaction, response)).to be_success
  end

  it "keeps one credential when two strict-account removals compete" do
    first, session = enroll
    transaction, response, = registration(session: session)
    second = service.register(transaction: transaction, credential_response: response, user: user, session: session, browser_secret: browser_secret).credential
    transaction, response = assertion(session: session, purpose: :manage_policy, allow_credentials: [first.external_id])
    elevated = authenticate(transaction, response, session: session)
    strict = service.change_policy(user: user, session: elevated.session, strict: true, acknowledged: true)
    transaction, response = assertion(session: strict.session, purpose: :manage_passkeys, allow_credentials: [first.external_id])
    management = authenticate(transaction, response, session: strict.session)
    ready, go = Queue.new, Queue.new
    threads = [first, second].map do |credential|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          service.remove(user: user, session: management.session, id: credential.id)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    results = Timeout.timeout(10) { threads.map(&:value) }
    expect(results.count(&:success?)).to eq(1)
    expect(AddAuthCredential.where(revoked_at: nil).count).to eq(1)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "does not let a cancelled, expired, or altered-configuration ceremony grant access" do
    enroll
    transaction, response = assertion
    expect(service.cancel(transaction: transaction, browser_secret: browser_secret)).to be(true)
    expect(authenticate(transaction, response)).not_to be_success
    transaction, response = assertion
    AddAuthCeremony.last.update!(expires_at: Time.current)
    expect(authenticate(transaction, response)).not_to be_success
    transaction, response = assertion
    AddAuthCeremony.last.update!(configuration_digest: "changed")
    expect(authenticate(transaction, response)).not_to be_success
  end

  it "denies malformed, oversized and cross-origin browser payloads without persistence changes" do
    enroll
    transaction, response = assertion
    [nil, [], {}, response.merge("rawId" => "different"), response.merge("extra" => "x" * 70_000), response.merge("response" => {"clientDataJSON" => Base64.urlsafe_encode64("{invalid")})].each do |value|
      expect(authenticate(transaction, value)).not_to be_success
    end
    data = JSON.parse(Base64.urlsafe_decode64(response["response"]["clientDataJSON"]))
    data["crossOrigin"] = true
    response["response"]["clientDataJSON"] = Base64.urlsafe_encode64(JSON.generate(data), padding: false)
    expect(authenticate(transaction, response)).not_to be_success
    expect(AddAuthCeremony.last.consumed_at).to be_nil
  end

  it "spends an assertion only once across competing database connections" do
    credential, = enroll
    transaction, response = assertion
    ready, go = Queue.new, Queue.new
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          authenticate(transaction, response)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    results = Timeout.timeout(10) { threads.map(&:value) }
    expect(results.count(&:success?)).to eq(1)
    expect(credential.reload.sign_count).to eq(1)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "preserves counter, ceremony and session state if finalization fails" do
    credential, = enroll
    transaction, response = assertion
    count = Session.count
    allow(Session).to receive(:create!).and_raise(ActiveRecord::RecordNotSaved)
    expect { authenticate(transaction, response) }.to raise_error(ActiveRecord::RecordNotSaved)
    expect(credential.reload.sign_count).to eq(0)
    expect(AddAuthCeremony.last.consumed_at).to be_nil
    expect(Session.count).to eq(count)
  end

  it "enforces strict policy across password, email, reset, session resume and last-credential removal" do
    credential, session = enroll
    transaction, response = assertion(session: session, purpose: :manage_policy)
    proof = authenticate(transaction, response, session: session)
    expect(proof).to be_success
    transition = service.change_policy(user: user, session: proof.session, strict: true, acknowledged: true)
    expect(transition).to be_success
    expect(user.reload.add_auth_strict).to be(true)
    expect(runtime.sessions.start(user: user, method: :password)).to be_nil
    expect(runtime.sessions.start(user: user, method: :email_link)).to be_nil
    expect(runtime.sessions.resume(signed_value: transition.credential.bearer)).to be_present
    transaction, response = assertion(session: transition.session, purpose: :manage_passkeys)
    management = authenticate(transaction, response, session: transition.session)
    expect(management).to be_success
    expect(service.remove(user: user, session: management.session, id: credential.id)).not_to be_success
    user.update!(password: "replacement-password")
    expect(user.reload.add_auth_strict).to be(true)
    expect(runtime.sessions.start(user: user, method: :password)).to be_nil
    expect(runtime.sessions.resume(signed_value: management.credential.bearer)).to be_nil
    AddAuth.configuration.passkeys.enabled = false
    expect(runtime.sessions.start(user: user, method: :password)).to be_nil
  end
end

require_relative "../../support/passkey_contract"
RSpec.describe "Production passkey store contract", database: true do
  let!(:user) { User.create!(email_address: "contract@example.test", password: "correct-password") }
  let(:store) { AddAuth::Rails::Stores::Passkeys.new(user_model: User, session_model: Session, credential_model: AddAuthCredential, ceremony_model: AddAuthCeremony, token_model: AddAuthSignInToken) }
  let(:session_store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  include_examples "passkey store contract"
end
