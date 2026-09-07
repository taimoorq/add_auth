# frozen_string_literal: true

require "rails_helper"
require "timeout"
require_relative "../../support/reauthentication"

RSpec.describe "Purpose-bound email reauthentication", database: true do
  include_context "public reauthentication"
  let!(:user) { User.create!(email_address: "reauth@example.test", password: "correct-password") }
  let(:runtime) { Latchkey::Rails::Runtime }
  let(:initial) { runtime.sessions.start(user: user, method: :password) }
  let(:secret) { runtime.browser_binding.generate }
  let(:email) { runtime.email(purpose: :reauthentication) }

  def issue(session: initial.session, purpose: :manage_profile)
    email.issue(identifier: user.email_address, browser_digest: runtime.browser_binding.digest(secret),
      session_id: session.id, session_digest: session.token_digest, authentication_purpose: purpose)
    record = LatchkeySignInToken.last
    [record, email.delivery_token(digest: record.digest)]
  end

  def confirm(raw, session: initial.session, browser: secret)
    email.reauthenticate(token: raw, session: session, browser_secret: browser)
  end

  it "atomically spends email proof, rotates one session and persists bounded current evidence" do
    old_bearer = initial.bearer
    record, raw = issue
    result = confirm(raw)
    expect(result).to be_success
    expect(Session.count).to eq(1)
    expect(record.reload.consumed_at).to be_present
    expect(result.session.id).to eq(initial.session.id)
    expect(result.session.elevation_version).not_to eq(user.password_digest)
    expect(runtime.sessions.resume(signed_value: old_bearer)).to be_nil
    expect(runtime.sessions.resume(signed_value: result.credential.bearer)).to be_present
    expect(confirm(raw)).not_to be_success
    expect(runtime.sessions.with_elevation(user: user, session: result.session,
      purpose: :manage_profile, policy: runtime.step_up_policy)).to be_success
    expect(runtime.sessions.with_elevation(user: user, session: result.session,
      purpose: :export, policy: runtime.step_up_policy)).not_to be_success
  end

  it "requires the original browser, account and bearer generation without burning on mismatch" do
    record, raw = issue
    other = runtime.sessions.start(user: user, method: :password)
    expect(confirm(raw, session: other.session)).not_to be_success
    expect(confirm(raw, browser: runtime.browser_binding.generate)).not_to be_success
    expect(confirm(raw, session: nil)).not_to be_success
    expect(record.reload.consumed_at).to be_nil
    expect(confirm(raw)).to be_success
  end

  it "never accepts ordinary sign-in proof as reauthentication or the reverse" do
    record, raw = issue
    expect { runtime.email.consume(token: raw) { |_account, persist| persist.call } }.not_to change(Session, :count)
    runtime.email.issue(identifier: user.email_address)
    ordinary = LatchkeySignInToken.last
    expect(confirm(runtime.email.delivery_token(digest: ordinary.digest))).not_to be_success
    expect(record.reload.revoked_at).to be_nil
    expect(confirm(raw)).to be_success
  end

  it "scopes resends to the initiating session and authentication purpose" do
    first, first_raw = issue
    second, second_raw = issue(purpose: :export)
    third, third_raw = issue
    expect(first.reload.revoked_at).to be_present
    expect(second.reload.revoked_at).to be_nil
    expect(email.delivery_token(digest: third.digest)).to eq(third_raw)
    expect(confirm(first_raw)).not_to be_success
    expect(confirm(second_raw)).to be_success
    expect(confirm(third_raw)).not_to be_success # old bearer after another elevation
  end

  it "rolls back token consumption and bearer rotation together on a persistence failure" do
    record, raw = issue
    old_digest = initial.session.token_digest
    allow_any_instance_of(LatchkeySignInToken).to receive(:update!).and_raise(ActiveRecord::RecordNotSaved)
    expect { confirm(raw) }.to raise_error(ActiveRecord::RecordNotSaved)
    expect(record.reload.consumed_at).to be_nil
    expect(initial.session.reload.token_digest).to eq(old_digest)
    expect(initial.session.elevated_at).to be_nil
  end

  it "rejects expired proof and disabled accounts at consumption" do
    record, raw = issue
    record.update!(expires_at: Time.current)
    expect(confirm(raw)).not_to be_success
    record, raw = issue
    old = Latchkey.configuration.eligible
    Latchkey.configuration.eligible = ->(_) { false }
    expect(runtime.email(purpose: :reauthentication).reauthenticate(token: raw, session: initial.session, browser_secret: secret)).not_to be_success
    expect(record.reload.consumed_at).to be_nil
  ensure
    Latchkey.configuration.eligible = old if old
  end

  it "rejects a changed policy and expired or revoked durable grants at mutation time" do
    _record, raw = issue
    result = confirm(raw)
    row = result.session
    Latchkey.configuration.step_up.purposes[:manage_profile] = {methods: [:passkey], require_passkey: true}
    expect(runtime.sessions.with_elevation(user: user, session: row,
      purpose: :manage_profile, policy: runtime.step_up_policy)).not_to be_success
    Latchkey.configuration.step_up.purposes[:manage_profile] = {methods: [:email_link]}
    row.update!(elevation_expires_at: Time.current)
    expect(runtime.sessions.with_elevation(user: user, session: row,
      purpose: :manage_profile, policy: runtime.step_up_policy)).not_to be_success
    row.update!(elevation_expires_at: 10.minutes.from_now, revoked_at: Time.current)
    expect(runtime.sessions.with_elevation(user: user, session: row,
      purpose: :manage_profile, policy: runtime.step_up_policy)).not_to be_success
  end

  it "allows only one competing email consumer on separate database connections" do
    _record, raw = issue
    snapshot = initial.session
    ready, go = Queue.new, Queue.new
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          runtime.email(purpose: :reauthentication).reauthenticate(token: raw, session: snapshot, browser_secret: secret)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    results = Timeout.timeout(10) { threads.map(&:value) }
    expect(results.count(&:success?)).to eq(1)
    expect(Session.count).to eq(1)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "does not return authority when a before-commit callback silently rolls back" do
    callback = -> { raise ActiveRecord::Rollback }
    Session.before_commit(callback)
    expect { initial }.to raise_error(Latchkey::Error, /rolled back/)
    expect(Session.count).to eq(0)
  ensure
    Session.skip_callback(:before_commit, :before, callback)
  end
end
