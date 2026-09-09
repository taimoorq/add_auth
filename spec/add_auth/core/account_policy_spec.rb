# frozen_string_literal: true

require "spec_helper"

RSpec.describe AddAuth::Core::AccountPolicy do
  let(:now) { Time.utc(2026, 9, 8) }
  let(:user) do
    Struct.new(:add_auth_authority, :confirmed_at, :unconfirmed_email, :locked_at,
      :add_auth_locked_until, :add_auth_manual_lock, :disabled_at, :deleted_at, :add_auth_strict).new(
        add_auth_authority: "add_auth", confirmed_at: now
      )
  end
  subject(:policy) { described_class.new(enabled: true, clock: double(now: now)) }

  it "rejects unknown or source-owned authority even with lifecycle disabled" do
    [nil, "devise", "unexpected"].each do |authority|
      user.add_auth_authority = authority
      expect(described_class.new(enabled: false).allowed?(user)).to be(false)
    end
    expect(described_class.new(enabled: false).allowed?(Object.new)).to be(true)
  end

  it "allows confirmation without granting an unconfirmed account sign-in" do
    user.confirmed_at = nil
    expect(policy.allowed?(user, purpose: :confirm)).to be(true)
    %i[sign_in manage reset_password].each { |purpose| expect(policy.allowed?(user, purpose: purpose)).to be(false) }
    user.confirmed_at = now
    expect(policy.allowed?(user, purpose: :confirm)).to be(false)
    user.unconfirmed_email = "pending@example.test"
    expect(policy.allowed?(user, purpose: :confirm)).to be(true)
    expect(policy.allowed?(user)).to be(true)
  end

  it "distinguishes timed expiry from manual suspension and strict recovery" do
    user.locked_at = now - 600
    user.add_auth_locked_until = now + 1
    expect(policy.allowed?(user)).to be(false)
    expect(policy.allowed?(user, purpose: :unlock)).to be(true)
    user.add_auth_locked_until = now
    expect(policy.allowed?(user)).to be(true)
    user.add_auth_manual_lock = true
    expect(policy.allowed?(user)).to be(false)
    expect(policy.allowed?(user, purpose: :unlock)).to be(false)
    user.add_auth_strict = true
    expect(policy.allowed?(user, purpose: :reset_password)).to be(false)
  end

  it "rejects every purpose for suspended, deleted, missing or host-ineligible accounts" do
    %i[disabled_at deleted_at].each do |field|
      user[field] = now
      %i[sign_in manage confirm reset_password unlock].each { |purpose| expect(policy.allowed?(user, purpose: purpose)).to be(false) }
      user[field] = nil
    end
    expect(policy.allowed?(nil)).to be(false)
    expect(policy.allowed?(user, purpose: :unknown)).to be(false)
    expect(described_class.new(enabled: true, eligible: ->(_) { false }).allowed?(user)).to be(false)
  end
end
