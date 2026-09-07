# frozen_string_literal: true

require "rails_helper"
require_relative "../../support/passkeys"

RSpec.describe "Explicit passkey recovery", database: true do
  include_context "passkey services"

  around do |example|
    previous = AddAuth.configuration.trusted_recovery_address
    AddAuth.configuration.trusted_recovery_address = ->(account) { account.email_address }
    example.run
  ensure
    AddAuth.configuration.trusted_recovery_address = previous
  end

  def recovery_link
    mail = runtime.email(purpose: :recovery)
    mail.issue(identifier: user.email_address)
    record = AddAuthSignInToken.last
    [mail, record, mail.delivery_token(digest: record.digest)]
  end

  it "grants explicit replacement enrollment and invalidates other authority only after replacement commits" do
    lost, old_session = enroll
    other = runtime.sessions.start(user: user, method: :password)
    mail, record, raw = recovery_link
    expect(runtime.email.preview(token: raw)).to be_nil
    recovered = mail.consume(token: raw)
    expect(recovered).to be_success
    expect(recovered.grant).to be_present
    expect(record.reload.consumed_at).to be_present
    expect(recovered.session.elevation_purpose).to eq("recover_passkeys")
    expect(runtime.sessions.with_elevation(user: user, session: recovered.session, purpose: :strong, policy: runtime.step_up_policy)).not_to be_success
    expect(lost.reload.revoked_at).to be_nil
    expect(service.remove(user: user, session: recovered.session, id: lost.id).reason).to eq(:elevation_required)
    expect(lost.reload.revoked_at).to be_nil
    options = service.registration_options(user: user, session: recovered.session, browser_secret: browser_secret)
    expect(options).to be_success
    response = client.create(challenge: options.credential[:publicKey][:challenge], user_verified: true)
    result = service.register(transaction: options.credential[:transaction], credential_response: response,
      user: user, session: recovered.session, browser_secret: browser_secret)
    expect(result).to be_success
    expect(result.grant).to be_present
    expect(result.session.elevated_at).to be_nil
    expect(other.session.reload.revoked_at).to be_present
    expect(old_session.reload.revoked_at).to be_present
    expect(lost.reload.revoked_at).to be_nil # explicitly review/remove lost keys
    expect(runtime.sessions.resume(signed_value: recovered.grant.bearer)).to be_nil
    expect(runtime.sessions.resume(signed_value: result.grant.bearer)).to be_present
    expect(events.map { |event| event[:kind] }).to include(:recovery_completed)
  end

  it "never mints recovery grants through ordinary public reauthentication purposes" do
    grant = initial
    expect(runtime.step_up_policy.reauthentication_rule_for(:recover_passkeys)).to be_nil
    mail = runtime.email(purpose: :reauthentication)
    mail.issue(identifier: user.email_address, session_id: grant.session.id, session_digest: grant.session.token_digest,
      browser_digest: runtime.browser_binding.digest(browser_secret), authentication_purpose: :recover_passkeys)
    expect(AddAuthSignInToken.count).to eq(0)
  end

  it "requires a trusted recovery address and denies strict accounts even after a reset" do
    user.update!(add_auth_strict: true)
    runtime.email(purpose: :recovery).issue(identifier: user.email_address)
    expect(AddAuthSignInToken.count).to eq(0)
    user.update!(password: "new-password")
    runtime.email(purpose: :recovery).issue(identifier: user.email_address)
    expect(AddAuthSignInToken.count).to eq(0)
    user.update!(add_auth_strict: false)
    AddAuth.configuration.trusted_recovery_address = ->(_account) {}
    runtime.email(purpose: :recovery).issue(identifier: user.email_address)
    expect(AddAuthSignInToken.count).to eq(0)
  end

  it "preserves existing credentials when recovery is cancelled or its replacement grant expires" do
    lost, = enroll
    mail, _record, raw = recovery_link
    recovered = mail.consume(token: raw)
    recovered.session.update!(elevation_expires_at: Time.current)
    expect(service.registration_options(user: user, session: recovered.session, browser_secret: browser_secret)).not_to be_success
    expect(lost.reload.revoked_at).to be_nil
    expect(mail.consume(token: raw)).not_to be_success
    expect(AddAuthCredential.count).to eq(1)
  end
end
