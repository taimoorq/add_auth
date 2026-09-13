# frozen_string_literal: true

# Executed inside a separately installed candidate and real generated Rails host.
require "rspec/autorun"
require "timeout"
require "add_auth/rails/doctor"

RSpec.describe "Installed optional-confirmation lifecycle" do
  let(:runtime) { AddAuth::Rails::Runtime }
  let(:config) { AddAuth.configuration }
  let(:password) { "current-account-password" }
  let(:email) { "account-#{SecureRandom.hex(6)}@example.test" }
  let(:client) { ActionDispatch::Integration::Session.new(Rails.application) }

  around do |example|
    lifecycle = config.lifecycle.to_h
    eligibility, passwords = config.eligible, config.passwords_enabled
    adapter = ActiveJob::Base.queue_adapter
    csrf = ActionController::Base.allow_forgery_protection
    config.lifecycle.confirmation_required = false
    config.rate_limit_store.clear
    ActionController::Base.allow_forgery_protection = true
    example.run
  ensure
    lifecycle.each { |key, value| config.lifecycle.public_send("#{key}=", value) }
    config.eligible, config.passwords_enabled = eligibility, passwords
    ActiveJob::Base.queue_adapter = adapter
    ActionController::Base.allow_forgery_protection = csrf
    Current.reset
  end

  def csrf(path = "/account/sign-up")
    client.get(path)
    Nokogiri::HTML(client.response.body).at_css('meta[name="csrf-token"]')["content"]
  end

  def register(**options)
    runtime.accounts.register(identifier: email, password: password, **options)
  end

  def signup(**parameters)
    client.post "/account/sign-up", params: {email_address: email, password: password, authenticity_token: csrf}.merge(parameters)
  end

  def proof_for(user, purpose)
    runtime.accounts.issue(identifier: user.email_address, purpose: purpose)
    record = AddAuthAccountToken.where(user_id: user.id, purpose: purpose.to_s).order(:id).last
    [record, record && runtime.accounts.claim_delivery(digest: record.digest)&.fetch(:token)]
  end

  def elevate(user, grant, purpose)
    runtime.elevate_password(user: user, session: grant.session, purpose: purpose,
      password: password, ip: "127.0.0.1", challenge_token: nil)
  end

  def race(count, &operation)
    ready, go = Queue.new, Queue.new
    threads = Array.new(count) do |index|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          operation.call(index)
        end
      end
    end
    Timeout.timeout(30) do
      count.times { ready.pop }
      count.times { go << true }
      threads.map(&:value)
    end
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "keeps the required-confirmation default and its pending/confirm/provision behavior" do
    config.lifecycle.confirmation_required = true
    expect(AddAuth::Configuration.new.lifecycle.confirmation_required).to be(true)
    expect(AddAuth::Configuration.new.lifecycle.reset_unconfirmed).to be(false)
    signup
    expect(client.response.status).to eq(303)
    expect(client.response.location).to end_with("/account/check-email")
    account = User.find_by!(email_address: email)
    expect(account.confirmed_at).to be_nil
    expect(account.provision_count).to eq(0)
    expect(Session.where(user_id: account.id)).to be_empty
    expect(runtime.sessions.start(user: account, method: :password)).to be_nil
    record, token = proof_for(account, :confirm)
    expect(runtime.accounts.consume(token: token, purpose: :confirm)).to be_success
    expect(account.reload.confirmed_at).to be_present
    expect(account.provision_count).to eq(1)
    expect(runtime.accounts.consume(token: token, purpose: :confirm).reason).to eq(:consumed_token)
    expect(record.reload.consumed_at).to be_present
  end

  it "boots the complete initializer and passes doctor without enabling email sign-in or providers" do
    expect(config.email_link.enabled).to be(false)
    expect(config.passkeys.enabled).to be(false)
    expect(config.external_identities.enabled).to be(false)
    expect(config.mobile.enabled).to be(false)
    expect(AddAuth::Rails::Doctor.new.call).to be_empty
    config.lifecycle.confirmation_required = "false"
    expect(AddAuth::Rails::Doctor.new.call.join).to include("confirmation")
    expect { runtime.accounts }.to raise_error(ArgumentError)
    config.lifecycle.confirmation_required = false
    allow(User).to receive(:column_names).and_return(User.column_names - ["add_auth_provisioned_at"])
    expect { runtime.accounts }.to raise_error(AddAuth::Error, /migrate/)
  end

  it "registers through CSRF/session wiring without confirmation, SMTP, or job enqueue" do
    expect(AddAuth::AccountDeliveryJob).not_to receive(:perform_later)
    expect(AddAuth::AccountMailer).not_to receive(:link)
    signup(confirmed_at: Time.current, add_auth_authority: "devise", add_auth_provisioned_at: Time.current)
    expect(client.response.status).to eq(303)
    expect(client.response.location).to end_with("/")
    account = User.find_by!(email_address: email)
    expect(account.confirmed_at).to be_nil
    expect(account.add_auth_authority).to eq("add_auth")
    expect(account.provision_count).to eq(1)
    expect(account.add_auth_provisioned_at).to be_present
    expect(AddAuthAccountToken.where(user_id: account.id)).to be_empty
    expect(Session.where(user_id: account.id).count).to eq(1)
    expect(Session.find_by!(user_id: account.id).authenticated_with).to eq("password")
    Current.reset
    client.get "/"
    expect(client.response.status).to eq(200)
    expect(client.response.body).to include(email)
    expect(runtime.trusted_recovery_address(account)).to be_nil
    expect(runtime.access_policy.recovery_address(account)).to be_nil
    expect(runtime.step_up_policy.methods_for(user: account, purpose: :change_email)).to eq([:password])
  end

  it "never authenticates duplicates or changes their password, even after a lost signup response" do
    first = register
    account, grant = first.user, first.grant
    expect(first).to be_success
    2.times do
      result = runtime.accounts.register(identifier: email.upcase, password: "attacker-chosen-password")
      expect(result.grant).to be_nil
      expect(result.user).to be_nil
    end
    signup(password: "attacker-chosen-password")
    expect(client.response.status).to eq(303)
    expect(client.response.location).to end_with("/sign-in")
    Current.reset
    client.get "/"
    expect(client.response.status).to eq(302)
    expect(account.reload.authenticate(password)).to be_truthy
    expect(account.authenticate("attacker-chosen-password")).to be(false)
    expect(account.provision_count).to eq(1)
    expect(Session.where(user_id: account.id).count).to eq(1)
    expect(runtime.sessions.resume(signed_value: grant.bearer)).to be_present
  end

  it "rolls back failed provisioning and lets a subsequent retry create exactly one account" do
    original = config.lifecycle.provision
    config.lifecycle.provision = ->(user) {
      user.update_columns(provision_count: 1)
      raise AddAuth::Error, "synthetic provisioning outage"
    }
    before_counts = [User.count, Session.count, AddAuthAddressClaim.count]
    signup
    expect(client.response.status).to eq(503)
    expect([User.count, Session.count, AddAuthAddressClaim.count]).to eq(before_counts)
    config.lifecycle.provision = original
    signup
    expect(client.response.status).to eq(303)
    expect(User.find_by!(email_address: email).provision_count).to eq(1)
  end

  it "rolls back session failure and aborts outer transactions and precommit rollback" do
    before_counts = [User.count, Session.count, AddAuthAddressClaim.count]
    failure = -> { raise AddAuth::Error, "synthetic session failure" }
    Session.set_callback(:create, :before, failure)
    expect { register }.to raise_error(AddAuth::Error)
    expect([User.count, Session.count, AddAuthAddressClaim.count]).to eq(before_counts)
    Session.skip_callback(:create, :before, failure)
    expect { User.transaction { register } }.to raise_error(AddAuth::Error, /own its transaction/)
    rollback = -> { raise ActiveRecord::Rollback }
    User.set_callback(:before_commit, :before, rollback)
    expect { register }.to raise_error(AddAuth::Error, /rolled back/)
    expect([User.count, Session.count, AddAuthAddressClaim.count]).to eq(before_counts)
  ensure
    Session.skip_callback(:create, :before, failure, raise: false) if failure
    User.skip_callback(:before_commit, :before, rollback, raise: false) if rollback
  end

  it "rechecks denial and strict states after provisioning and discards every provisional write" do
    before_counts = [User.count, Session.count, AddAuthAddressClaim.count]
    {disabled_at: Time.current, deleted_at: Time.current, locked_at: Time.current,
     add_auth_authority: "devise", add_auth_strict: true, access_state: "suspended",
     confirmed_at: Time.current, email_address: "rewritten@example.test", password_digest: "rewritten", unconfirmed_email: "rewritten@example.test"}.each do |field, value|
      config.lifecycle.provision = ->(user) { user.update_columns(field => value, :provision_count => 1) }
      expect(register).to be_failure
      expect([User.count, Session.count, AddAuthAddressClaim.count]).to eq(before_counts)
    end
    config.lifecycle.eligible = ->(_user) { false }
    expect(register.grant).to be_nil
    expect([User.count, Session.count, AddAuthAddressClaim.count]).to eq(before_counts)
  end

  it "respects host admission at proof issuance and denies resumed sessions after suspension" do
    result = register
    account = result.user
    config.lifecycle.reset_unconfirmed = true
    record, token = proof_for(account, :reset_password)
    account.update_columns(access_state: "suspended")
    expect(runtime.sessions.resume(signed_value: result.grant.bearer)).to be_nil
    expect(runtime.accounts.consume(token: token, purpose: :reset_password, password: "replacement-password")).to be_failure
    expect(record.reload.consumed_at).to be_nil
    expect { runtime.accounts.issue(identifier: email, purpose: :reset_password) }.not_to change(AddAuthAccountToken, :count)
    expect { runtime.accounts.issue(identifier: email, purpose: :confirm) }.not_to change(AddAuthAccountToken, :count)
  end

  it "has one registration winner and provisions only once across concurrent registration and later confirmation" do
    results = race(2) { register }
    expect(results.count { |result| result.grant }).to eq(1)
    account = User.find_by!(email_address: email)
    expect(User.where(email_address: email).count).to eq(1)
    expect(account.provision_count).to eq(1)
    expect(Session.where(user_id: account.id).count).to eq(1)
    record, token = proof_for(account, :confirm)
    config.lifecycle.confirmation_required = true
    outcomes = race(2) { runtime.accounts.consume(token: token, purpose: :confirm) }
    expect(outcomes.count(&:success?)).to eq(1)
    expect(account.reload.provision_count).to eq(1)
    expect(account.confirmed_at).to be_present
    expect(record.reload.consumed_at).to be_present
  end

  it "requires explicit unconfirmed reset policy and exact single-use proof without changing verification" do
    result = register
    account = result.user
    expect { runtime.accounts.issue(identifier: email, purpose: :reset_password) }.not_to change(AddAuthAccountToken, :count)
    config.lifecycle.reset_unconfirmed = true
    record, token = proof_for(account, :reset_password)
    expect(token).to be_present
    expect(runtime.accounts.preview(token: token, purpose: :reset_password)).to be_success
    expect(record.reload.consumed_at).to be_nil
    expect(runtime.accounts.consume(token: token, purpose: :confirm)).to be_failure
    expect(runtime.accounts.consume(token: token, purpose: :reset_password, password: "short")).to be_failure
    expect(record.reload.consumed_at).to be_nil
    outcomes = race(2) { |index| runtime.accounts.consume(token: token, purpose: :reset_password, password: "reset-password-#{index}") }
    expect(outcomes.count(&:success?)).to eq(1)
    expect(runtime.sessions.resume(signed_value: result.grant.bearer)).to be_nil
    expect(account.reload.confirmed_at).to be_nil
    expect(account.provision_count).to eq(1)
    expect(Session.where(user_id: account.id, revoked_at: nil)).to be_empty
    expect(runtime.accounts.consume(token: token, purpose: :reset_password, password: password)).to be_failure
    expect(runtime.trusted_recovery_address(account)).to be_nil
  end

  it "invalidates unconfirmed reset on address/password changes, strict policy, expiry and policy withdrawal" do
    account = register.user
    config.lifecycle.reset_unconfirmed = true
    record, token = proof_for(account, :reset_password)
    {unconfirmed_email: "pending@example.test", password_digest: "changed", add_auth_strict: true,
     disabled_at: Time.current, deleted_at: Time.current, add_auth_authority: "devise"}.each do |field, value|
      original = account.public_send(field)
      account.update_columns(field => value)
      expect(runtime.accounts.consume(token: token, purpose: :reset_password, password: "replacement-password")).to be_failure
      expect(record.reload.consumed_at).to be_nil
      account.update_columns(field => original)
    end
    config.lifecycle.reset_unconfirmed = false
    expect(runtime.accounts.consume(token: token, purpose: :reset_password, password: "replacement-password")).to be_failure
    config.lifecycle.reset_unconfirmed = true
    record.update!(expires_at: Time.current - 1)
    expect(runtime.accounts.consume(token: token, purpose: :reset_password, password: "replacement-password").reason).to eq(:expired_token)
  end

  it "keeps lockout and trusted-only unlock behavior effective for optional accounts" do
    account = register.user
    config.lifecycle.maximum_attempts = 2
    2.times do
      runtime.sessions.authenticate(identifier: email, password: "wrong") { runtime.authenticate_password(identifier: email, password: "wrong") }
    end
    expect(account.reload.failed_attempts).to eq(2)
    expect(account.locked_at).to be_present
    expect(runtime.sessions.start(user: account, method: :password)).to be_nil
    expect(AddAuthAccountToken.where(user_id: account.id, purpose: "unlock")).to be_empty
    expect(Session.where(user_id: account.id, revoked_at: nil)).to be_empty
  end

  it "keeps address changes proof-bound and revokes authority after the new address is confirmed" do
    result = register
    account = result.user
    changed = "new-#{email}"
    expect(runtime.accounts.change_email(user: account, session: result.session, identifier: changed).reason).to eq(:elevation_required)
    config.lifecycle.reset_unconfirmed = true
    _reset, reset_token = proof_for(account, :reset_password)
    elevated = elevate(account, result.grant, :change_email)
    expect(elevated).to be_success
    expect(runtime.accounts.change_email(user: account, session: elevated.session, identifier: changed)).to be_success
    expect(account.reload.email_address).to eq(email)
    expect(account.confirmed_at).to be_nil
    expect(runtime.accounts.consume(token: reset_token, purpose: :reset_password, password: "replacement-password")).to be_failure
    record, token = proof_for(account, :confirm)
    expect(runtime.accounts.preview(token: token, purpose: :confirm)).to be_success
    expect(account.reload.email_address).to eq(email)
    expect(runtime.accounts.consume(token: token, purpose: :confirm)).to be_success
    expect(account.reload.email_address).to eq(changed)
    expect(account.confirmed_at).to be_present
    expect(account.provision_count).to eq(1)
    expect(runtime.sessions.resume(signed_value: elevated.credential.bearer)).to be_nil
    expect(record.reload.consumed_at).to be_present
  end

  it "locks and revokes the replaced browser only on committed registration" do
    initial = register
    other = runtime.accounts.register(identifier: "other-#{email}", password: password, replacing: initial.session)
    expect(other.grant).to be_present
    expect(runtime.sessions.resume(signed_value: initial.grant.bearer)).to be_nil
    preserved = other.grant
    config.lifecycle.provision = ->(_) { raise AddAuth::Error, "synthetic failure" }
    expect { runtime.accounts.register(identifier: "failed-#{email}", password: password, replacing: other.session) }.to raise_error(AddAuth::Error)
    expect(runtime.sessions.resume(signed_value: preserved.bearer)).to be_present
  end

  it "keeps disabled email and reauthentication routes inert without enqueuing jobs" do
    signup
    token = csrf("/sign-in")
    [["/sign-in/email", :post], ["/sign-in/link", :post], ["/sign-in/link", :get],
      ["/sign-in/check-email", :get], ["/reauthenticate/email", :post], ["/reauthenticate/link", :post],
      ["/reauthenticate/link", :get], ["/reauthenticate/check-email", :get]].each do |path, method|
      expect do
        client.public_send(method, path, params: {purpose: "change_email", email_address: email, authenticity_token: token})
      end.not_to change { ActiveJob::Base.queue_adapter.enqueued_jobs.length }
      expect(client.response.status).to eq(404), path
    end
  end

  it "uses 422 shared HTML and Turbo validation and does not retain submitted passwords" do
    signup(password: "short")
    expect(client.response.status).to eq(422)
    expect(client.response.body).to include(email)
    expect(client.response.body).not_to include('value="short"')
    client.post "/account/sign-up", params: {email_address: email, password: "short", authenticity_token: csrf}, headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(client.response.status).to eq(422)
    expect(client.response.body).to include('target="add_auth-content"')
    expect(client.response.headers["Cache-Control"]).to include("no-store")
    expect(User.exists?(email_address: email)).to be(false)
  end
end

require_relative "optional_confirmation_browser"
