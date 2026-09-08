# frozen_string_literal: true

# Rails runner payload for published_package.rb. All identities and secrets are
# synthetic and confined to the disposable host, never emitted in test output.
require "webauthn/fake_client"
require "add_auth/testing"
runtime = AddAuth::Rails::Runtime
file = Rails.root.join("tmp/upgrade-state.json")
phase = ENV.fetch("ADD_AUTH_UPGRADE_PHASE")

if phase == "seed"
  user = User.create!(email_address: "upgrade@example.test", password: "correct-password")
  normal = runtime.sessions.start(user: user, method: :password)
  revoked = runtime.sessions.start(user: user, method: :password)
  runtime.sessions.revoke(session: revoked.session)
  runtime.email.issue(identifier: user.email_address)
  mail = AddAuthSignInToken.last
  queued_user = User.create!(email_address: "queued@example.test", password: "correct-password")
  intake = runtime.enqueue_email(queued_user.email_address)

  strict = User.create!(email_address: "strict@example.test", password: "correct-password")
  initial = runtime.sessions.start(user: strict, method: :password)
  elevated = runtime.elevate_password(user: strict, session: initial.session, purpose: :manage_passkeys,
    password: "correct-password", ip: "127.0.0.1", challenge_token: nil).credential
  secret = runtime.browser_binding.generate
  client = WebAuthn::FakeClient.new("https://example.test", encoding: :base64url)
  options = runtime.passkeys.registration_options(user: strict, session: elevated.session, browser_secret: secret).credential
  response = client.create(challenge: options.fetch(:publicKey).fetch(:challenge), user_verified: true)
  registered = runtime.passkeys.register(transaction: options.fetch(:transaction), credential_response: response,
    user: strict, session: elevated.session, browser_secret: secret, nickname: "Preserved key")
  abort "baseline enrollment failed" unless registered.success?
  options = runtime.passkeys.authentication_options(user: strict, session: elevated.session,
    purpose: :manage_policy, browser_secret: secret).credential
  assertion = client.get(challenge: options.fetch(:publicKey).fetch(:challenge), user_verified: true,
    backup_state: false, user_handle: Base64.urlsafe_decode64(strict.reload.webauthn_id))
  proof = runtime.passkeys.authenticate(transaction: options.fetch(:transaction), credential_response: assertion,
    session: elevated.session, browser_secret: secret)
  abort "baseline policy proof failed" unless proof.success?
  policy = runtime.passkeys.change_policy(user: strict, session: proof.session, strict: true, acknowledged: true)
  abort "baseline strict activation failed" unless policy.success?
  pending = runtime.passkeys.authentication_options(browser_secret: secret).credential
  pending_response = client.get(challenge: pending.fetch(:publicKey).fetch(:challenge), user_verified: true,
    backup_state: false, user_handle: Base64.urlsafe_decode64(strict.webauthn_id))
  state = {normal: normal.bearer, revoked: revoked.bearer, strict: policy.credential.bearer,
           strict_id: strict.id, credential_id: registered.credential.id,
           mail_id: mail.id, mail_digest: mail.digest, intake: intake.serialize,
           transaction: pending.fetch(:transaction), assertion: pending_response, browser_secret: secret}
  File.write(file, JSON.generate(state), mode: "w", perm: 0o600)
  puts "upgrade state seeded"
else
  state = JSON.parse(File.read(file))
  abort "active session lost" unless runtime.sessions.resume(signed_value: state.fetch("normal"))
  abort "revoked session revived" if runtime.sessions.resume(signed_value: state.fetch("revoked"))
  strict = User.find(state.fetch("strict_id"))
  abort "strict account weakened" unless strict.add_auth_strict && runtime.sessions.start(user: strict, method: :password).nil?
  abort "strict session lost" unless runtime.sessions.resume(signed_value: state.fetch("strict"))
  abort "credential changed" unless AddAuthCredential.find(state.fetch("credential_id")).nickname == "Preserved key"
  response = runtime.passkeys.authenticate(transaction: state.fetch("transaction"), credential_response: state.fetch("assertion"),
    browser_secret: state.fetch("browser_secret"))
  if phase == "verify"
    abort "in-flight passkey lost" unless response.success?
    abort "passkey replay accepted" if runtime.passkeys.authenticate(transaction: state.fetch("transaction"),
      credential_response: state.fetch("assertion"), browser_secret: state.fetch("browser_secret")).success?
    ActiveJob::Base.execute(state.fetch("intake"))
    abort "old intake job lost" unless AddAuthSignInToken.exists?(request_id: state.fetch("intake").fetch("job_id"))
    AddAuth::EmailDeliveryJob.perform_now(state.fetch("mail_id"))
    record = AddAuthSignInToken.find(state.fetch("mail_id"))
    abort "pending mail changed or lost" unless record.delivered_at && record.delivery_payload.nil? && record.digest == state.fetch("mail_digest")
    link = AddAuth::Testing.delivered_link(ActionMailer::Base.deliveries.last, purpose: :sign_in)
    browser = ActionDispatch::Integration::Session.new(Rails.application)
    browser.host! "example.test"
    browser.get link.request_uri
    abort "scanner GET consumed link" if record.reload.consumed_at
    state["consumed_token"] = URI.decode_www_form(link.query).to_h.fetch("token")
    browser.post "/sign-in/link", params: {token: state.fetch("consumed_token"), switch_account: "1"}
    abort "upgraded mail sign-in failed" unless browser.response.status == 303 && record.reload.consumed_at
    browser.get "/sessions"
    abort "upgraded management missing" unless browser.response.status == 200
    browser.delete "/session"
    browser.get "/sign-in"
    abort "ejected customization lost" unless browser.response.body.include?("Host customization survives")
    File.write(file, JSON.generate(state), mode: "w", perm: 0o600)
    puts "upgrade authority verified"
  else
    abort "rollback revived passkey ceremony" if response.success?
    browser = ActionDispatch::Integration::Session.new(Rails.application)
    browser.post "/sign-in/link", params: {token: state.fetch("consumed_token"), switch_account: "1"}
    abort "rollback revived email proof" unless browser.response.status == 422
    before = ActionMailer::Base.deliveries.size
    AddAuth::EmailDeliveryJob.perform_now(state.fetch("mail_id"))
    abort "old worker redelivered spent proof" unless ActionMailer::Base.deliveries.size == before
    puts "rollback authority verified"
  end
end
