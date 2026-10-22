# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/passwords/lifecycle"

RSpec.describe AddAuth::Core::Passwords::Lifecycle do
  let(:now) { Time.utc(2026, 9, 8) }
  let(:clock) { double(now: now) }
  let(:user) do
    Struct.new(:failed_attempts, :locked_at, :add_auth_locked_until, :add_auth_manual_lock,
      :add_auth_password_scheme, :password_digest).new(
        failed_attempts: 0, add_auth_manual_lock: false, add_auth_password_scheme: "rails", password_digest: "current"
      )
  end
  let(:store) { double }
  let(:unlock) { double(call: nil) }
  let(:eligible) { ->(account) { !account.add_auth_manual_lock } }
  let(:password_allowed) { ->(account) { !account.password_digest.nil? } }
  subject(:lifecycle) do
    described_class.new(store: store, policy: eligible, enabled: true, maximum_attempts: 3, unlock_in: 600, clock: clock,
      issue_unlock: unlock, password_allowed: password_allowed)
  end

  before do
    allow(store).to receive(:update_account) do |user:, **attributes|
      attributes.each { |key, value| user.public_send("#{key}=", value) }
    end
    allow(store).to receive(:revoke_authority)
    allow(store).to receive(:rehash_password)
  end

  it "locks the password method at the exact threshold without revoking existing authority" do
    2.times { expect(lifecycle.verified(user: user, password: "wrong", valid: false)).to be(false) }
    expect(user.locked_at).to be_nil
    expect(lifecycle).not_to be_locked(user)
    lifecycle.verified(user: user, password: "wrong", valid: false)
    expect(user.locked_at).to eq(now)
    expect(user.add_auth_locked_until).to eq(now + 600)
    expect(lifecycle).to be_locked(user)
    expect(lifecycle.verified(user: user, password: "correct", valid: true)).to be(false)
    # Further guesses while locked are neither counted nor able to extend the lock.
    lifecycle.verified(user: user, password: "wrong", valid: false)
    expect(user.add_auth_locked_until).to eq(now + 600)
    expect(store).not_to have_received(:revoke_authority)
    expect(unlock).to have_received(:call).with(user).once
  end

  it "never counts failures for an account that cannot use password sign-in" do
    # Passkey-only, strict or password-less accounts: a stranger guessing at the
    # address must not be able to lock the owner out of anything.
    user.password_digest = nil
    10.times { expect(lifecycle.verified(user: user, password: "guess", valid: false)).to be(false) }
    expect(user.failed_attempts).to eq(0)
    expect(user.locked_at).to be_nil
    expect(store).not_to have_received(:update_account)
    expect(unlock).not_to have_received(:call)
    strict = described_class.new(store: store, policy: eligible, enabled: true, maximum_attempts: 3, unlock_in: 600, clock: clock,
      issue_unlock: unlock, password_allowed: ->(_account) { false })
    user.password_digest = "current"
    5.times { expect(strict.verified(user: user, password: "current", valid: true)).to be(false) }
    expect(user.failed_attempts).to eq(0)
  end

  it "keeps manual and untimed locks out of the automatic password gate" do
    user.locked_at = now
    user.add_auth_locked_until = now + 600
    user.add_auth_manual_lock = true
    expect(lifecycle).not_to be_locked(user)
    user.add_auth_manual_lock = false
    user.add_auth_locked_until = nil
    expect(lifecycle).not_to be_locked(user)
    disabled = described_class.new(store: store, policy: eligible, enabled: false, clock: clock)
    user.add_auth_locked_until = now + 600
    expect(disabled).not_to be_locked(user)
  end

  it "starts a new failure sequence after timed expiry but preserves a manual lock" do
    user.locked_at = now - 600
    user.add_auth_locked_until = now
    user.failed_attempts = 3
    user.add_auth_manual_lock = true
    lifecycle.prepare(user: user)
    expect(user.locked_at).not_to be_nil
    user.add_auth_manual_lock = false
    lifecycle.prepare(user: user)
    expect(user.locked_at).to be_nil
    lifecycle.verified(user: user, password: "wrong", valid: false)
    expect(user.failed_attempts).to eq(1)
    expect(user.locked_at).to be_nil
  end

  it "clears failures only after successful eligible authentication" do
    user.failed_attempts = 2
    lifecycle.verified(user: user, password: "correct", valid: true)
    expect(user.failed_attempts).to eq(0)
    expect(store).not_to have_received(:revoke_authority)
    expect(lifecycle.verified(user: nil, password: "wrong", valid: false)).to be(false)
  end

  it "rehashes an accepted historical password and retires previous authority" do
    user.add_auth_password_scheme = "devise_bcrypt"
    # Historical six-character passwords remain usable despite a stronger new
    # password policy. Rehash is a representation change after verified proof.
    expect(lifecycle.verified(user: user, password: "oldpwd", valid: true)).to be(true)
    expect(store).to have_received(:rehash_password).with(user: user, password: "oldpwd")
    expect(store).to have_received(:revoke_authority).with(user: user, at: now)
  end

  it "retains an accepted long legacy password until a supported reset" do
    user.add_auth_password_scheme = "devise_bcrypt"
    expect(lifecycle.verified(user: user, password: "é" * 37, valid: true)).to be(true)
    expect(store).not_to have_received(:rehash_password)
    expect(store).not_to have_received(:revoke_authority)
  end

  it "counts reauthentication failures but defers representation upgrade until a new sign-in" do
    user.add_auth_password_scheme = "devise_bcrypt"
    expect(lifecycle.verified(user: user, password: nil, valid: false, rehash: false)).to be(false)
    expect(user.failed_attempts).to eq(1)
    expect(lifecycle.verified(user: user, password: "oldpwd", valid: true, rehash: false)).to be(true)
    expect(user.failed_attempts).to eq(0)
    expect(store).not_to have_received(:rehash_password)
    expect(store).not_to have_received(:revoke_authority)
  end

  it "never rehashes wrong, denied or already-current passwords" do
    lifecycle.verified(user: user, password: "correct", valid: true)
    user.add_auth_password_scheme = "devise_bcrypt"
    lifecycle.verified(user: user, password: "wrong", valid: false)
    user.locked_at = now
    user.add_auth_locked_until = now + 60
    expect(lifecycle.verified(user: user, password: "correct", valid: true)).to be(false)
    expect(store).not_to have_received(:rehash_password)
  end
end
