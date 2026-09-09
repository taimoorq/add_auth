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
  let(:eligible) { ->(account) { !account.locked_at } }
  subject(:lifecycle) { described_class.new(store: store, policy: eligible, enabled: true, maximum_attempts: 3, unlock_in: 600, clock: clock, issue_unlock: unlock) }

  before do
    allow(store).to receive(:update_account) do |user:, **attributes|
      attributes.each { |key, value| user.public_send("#{key}=", value) }
    end
    allow(store).to receive(:revoke_authority)
    allow(store).to receive(:rehash_password)
  end

  it "locks at the exact threshold and revokes outstanding authority once" do
    2.times { expect(lifecycle.verified(user: user, password: "wrong", valid: false)).to be(false) }
    expect(user.locked_at).to be_nil
    expect(store).not_to have_received(:revoke_authority)
    lifecycle.verified(user: user, password: "wrong", valid: false)
    expect(user.locked_at).to eq(now)
    expect(user.add_auth_locked_until).to eq(now + 600)
    expect(lifecycle.verified(user: user, password: "correct", valid: true)).to be(false)
    expect(store).to have_received(:revoke_authority).with(user: user, at: now).once
    expect(unlock).to have_received(:call).with(user).once
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
    expect(lifecycle.verified(user: user, password: "correct", valid: true)).to be(false)
    expect(store).not_to have_received(:rehash_password)
  end
end
