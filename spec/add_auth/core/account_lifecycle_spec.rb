# frozen_string_literal: true

require "spec_helper"

RSpec.describe AddAuth::Core::AccountLifecycle do
  let(:now) { Time.utc(2026, 9, 8) }
  let(:clock) { double(now: now) }
  let(:account_type) do
    Struct.new(:id, :email_address, :password_digest, :add_auth_authority,
      :confirmed_at, :unconfirmed_email, :locked_at, :disabled_at, :deleted_at,
      :add_auth_manual_lock)
  end
  let(:proof_type) do
    Struct.new(:user, :purpose, :digest, :request_id, :address_digest,
      :account_version, :expires_at, :delivery_payload, :created_at,
      :consumed_at, :revoked_at)
  end
  let(:user) do
    account_type.new(id: 7, email_address: "account@example.test", password_digest: "current-version",
      add_auth_authority: "add_auth", confirmed_at: nil, unconfirmed_email: nil,
      locked_at: nil, disabled_at: nil, deleted_at: nil, add_auth_manual_lock: false)
  end
  let(:store) { double("transactional account store") }
  let(:digest) { AddAuth::Core::Digest::Hmac.new(salt: "account-test", secret: "secret" * 16) }
  let(:cipher) { double(encrypt: "encrypted payload") }
  let(:policy) { AddAuth::Core::AccountPolicy.new(enabled: true, clock: clock) }
  let(:notify) { double(call: nil) }
  let(:sessions) { double }
  let(:step_up) { double }
  let(:mapper) { ->(_profile) { {} } }
  let(:token) { "ac1:" + "a" * 43 }
  let(:record) { nil }
  subject(:accounts) do
    described_class.new(store: store, digest: digest, delivery_cipher: cipher, policy: policy,
      password_policy: ->(password) { password.length >= 12 && password.bytesize <= 72 },
      trusted_address: ->(account) { account.email_address }, clock: clock,
      random: double(uuid: "issuance", urlsafe_base64: "a" * 43), notify: notify,
      sessions: sessions, step_up_policy: step_up, profile_attributes: mapper)
  end

  before do
    allow(store).to receive(:with_user) { |**_, &block| block.call(user) }
    allow(store).to receive(:with_token) { |**_, &block| block.call(user, record) }
    allow(store).to receive(:inspect_token) { [user, record] }
    allow(store).to receive(:issued?).and_return(false)
    allow(store).to receive(:replace_pending) do |**attributes|
      @proof = proof_type.new(**attributes)
    end
    allow(store).to receive(:update_account) do |user:, **attributes|
      attributes.each { |field, value| user.public_send("#{field}=", value) }
    end
    allow(store).to receive(:consume) { |record:, at:| record.consumed_at = at }
    allow(store).to receive(:provision)
    allow(store).to receive(:revoke_authority)
  end

  it "validates registration before persistence and keeps duplicates generic" do
    expect(store).not_to receive(:create_account)
    ["short", "é" * 40, "long\0invalid-password", nil].each do |password|
      expect(accounts.register(identifier: user.email_address, password: password).reason).to eq(:invalid_credentials)
    end
    expect(accounts.register(identifier: "invalid", password: "valid-account-password").success?).to be(false)
  end

  it "reserves the address and records confirmation without provisioning or login" do
    allow(store).to receive(:create_account) { |**_, &block|
      block.call(user)
      :created
    }
    expect(store).to receive(:claim_address).with(user: user, digest: kind_of(String), address: user.email_address, state: "current")
    result = accounts.register(identifier: " Account@example.test ", password: "valid-account-password", profile: {admin: true})
    expect(result.success?).to be(true)
    expect(result.user).to be_nil
    expect(store).to have_received(:create_account).with(email: user.email_address, password: "valid-account-password", profile: {})
    expect(@proof.purpose).to eq("confirm")
    expect(store).not_to have_received(:provision)
    expect(store).not_to have_received(:revoke_authority)
    allow(store).to receive(:create_account).and_return(:duplicate)
    expect(accounts.register(identifier: user.email_address, password: "valid-account-password").user).to be_nil
    allow(store).to receive(:create_account).and_return(:invalid)
    expect(accounts.register(identifier: user.email_address, password: "valid-account-password").success?).to be(false)
  end

  context "with an explicit host profile mapper" do
    let(:mapper) { ->(profile) { profile.slice(:name, :consent, :add_auth_authority) } }

    it "passes reviewed name and consent fields through the host validation boundary" do
      expect(store).to receive(:create_account).with(email: user.email_address, password: "valid-account-password", profile: {name: "Reader", consent: true}).and_return(:invalid)
      expect(accounts.register(identifier: user.email_address, password: "valid-account-password", profile: {name: "Reader", consent: true, role: "admin"}).success?).to be(false)
    end

    it "rejects authentication authority in the mapped profile" do
      expect(store).not_to receive(:create_account)
      expect { accounts.register(identifier: user.email_address, password: "valid-account-password", profile: {add_auth_authority: "add_auth"}) }.to raise_error(AddAuth::Error, /host profile fields/)
    end
  end

  context "with an issued confirmation" do
    let(:record) { @proof }
    before { accounts.issue(identifier: user.email_address, purpose: :confirm) }

    it "keeps preview inert and provisions once on explicit consumption" do
      2.times { expect(accounts.preview(token: token, purpose: :confirm).success?).to be(true) }
      expect(record.consumed_at).to be_nil
      expect(accounts.consume(token: token, purpose: :confirm).success?).to be(true)
      expect(user.confirmed_at).to eq(now)
      expect(accounts.consume(token: token, purpose: :confirm).reason).to eq(:consumed_token)
      expect(store).to have_received(:provision).with(user: user).once
    end

    it "rejects wrong purpose, changed address or changed account state without consuming" do
      expect(accounts.consume(token: token, purpose: :reset_password, password: "valid-account-password").reason).to eq(:invalid_credentials)
      user.email_address = "changed@example.test"
      expect(accounts.consume(token: token, purpose: :confirm).success?).to be(false)
      user.email_address = "account@example.test"
      user.password_digest = "new-password-version"
      expect(accounts.consume(token: token, purpose: :confirm).success?).to be(false)
      expect(record.consumed_at).to be_nil
    end

    it "rejects expired and revoked proofs and malformed input" do
      record.expires_at = now
      expect(accounts.consume(token: token, purpose: :confirm).reason).to eq(:expired_token)
      record.expires_at = now + 60
      record.revoked_at = now
      expect(accounts.consume(token: token, purpose: :confirm).reason).to eq(:revoked_token)
      expect(accounts.preview(token: [], purpose: :confirm).reason).to eq(:invalid_credentials)
      expect(accounts.preview(token: token, purpose: :unknown).success?).to be(false)
    end
  end

  it "keeps unknown and ineligible account requests generic and does not issue proof" do
    user.disabled_at = now
    expect(accounts.issue(identifier: user.email_address, purpose: :reset_password).success?).to be(true)
    expect(accounts.issue(identifier: [], purpose: :reset_password).success?).to be(true)
    expect(accounts.issue(identifier: user.email_address, purpose: :unknown).success?).to be(false)
    expect(store).not_to have_received(:replace_pending)
  end

  it "requires current purpose-bound elevation for password changes" do
    expect(sessions).to receive(:with_elevation).with(user: user, session: :browser, purpose: :change_password, policy: step_up).and_return(AddAuth::Result.failure(reason: :elevation_required))
    expect(store).not_to receive(:replace_password)
    expect(accounts.change_password(user: user, session: :browser, password: "replacement-password").reason).to eq(:elevation_required)
  end

  it "fences direct address updates only when account lifecycle owns the fields" do
    expect { described_class.validate_host_write!(changes: {"email_address" => ["before", "after"]}, enabled: true) }.to raise_error(AddAuth::Error)
    expect { described_class.validate_host_write!(changes: {unconfirmed_email: [nil, "pending"]}, enabled: true) }.to raise_error(AddAuth::Error)
    expect { described_class.validate_host_write!(changes: {email_address: ["before", "after"]}, enabled: false) }.not_to raise_error
    expect { described_class.validate_host_write!(changes: {disabled_at: [nil, now]}, enabled: true) }.not_to raise_error
  end

  it "maps host password rejection without claiming a completed change" do
    user.confirmed_at = now
    allow(sessions).to receive(:with_elevation) { |**_, &block| block.call(user) }
    allow(store).to receive(:replace_password).and_raise(described_class::InvalidPassword)
    expect(accounts.change_password(user: user, session: :browser, password: "replacement-password").reason).to eq(:invalid_credentials)
    expect(store).not_to have_received(:revoke_authority)
    expect(notify).not_to have_received(:call)
  end

  it "changes passwords under the live grant and revokes every existing authority" do
    user.confirmed_at = now
    allow(sessions).to receive(:with_elevation) { |**_, &block|
      block.call(user)
      AddAuth::Result.success(user: user, strategy: :step_up)
    }
    expect(store).to receive(:replace_password).with(user: user, password: "replacement-password")
    expect(accounts.change_password(user: user, session: :browser, password: "replacement-password").success?).to be(true)
    expect(store).to have_received(:revoke_authority).with(user: user, at: now)
    expect(notify).to have_received(:call).with(user: user, kind: :password_changed, at: now)
    user.disabled_at = now
    expect(accounts.change_password(user: user, session: :browser, password: "replacement-password").success?).to be(false)
  end

  it "requires a separate deletion purpose and rolls host refusal into a failure" do
    expect(sessions).to receive(:with_elevation).with(user: user, session: :browser, purpose: :delete_account, policy: step_up).and_return(AddAuth::Result.failure(reason: :elevation_required))
    expect(accounts.delete_account(user: user, session: :browser).reason).to eq(:elevation_required)
    user.confirmed_at = now
    allow(sessions).to receive(:with_elevation) { |**_, &block| block.call(user) }
    allow(store).to receive(:delete_account).and_raise(described_class::DeletionRejected)
    expect(accounts.delete_account(user: user, session: :browser).reason).to eq(:invalid_credentials)
  end
end
