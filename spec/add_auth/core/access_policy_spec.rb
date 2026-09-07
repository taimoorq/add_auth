# frozen_string_literal: true

require "spec_helper"

RSpec.describe AddAuth::Core::AccessPolicy do
  let(:user) { Struct.new(:password_digest, :email_address, :add_auth_strict).new("digest", "user@example.test", false) }

  def policy(**options)
    described_class.new(credentials: ->(_) {}, passkeys_enabled: true, email_enabled: true,
      trusted_recovery_address: ->(account) { account.email_address }, **options)
  end

  it "preserves the stock password method by default" do
    expect(policy.sign_in_allowed?(user, :password)).to be(true)
  end

  it "rejects password proof when disabled while preserving enabled alternatives" do
    disabled = policy(password_enabled: false)
    expect(disabled.sign_in_allowed?(user, :password)).to be(false)
    expect(disabled.methods_for(user)).to contain_exactly(:email_link, :passkey)
    user.password_digest = nil
    expect(policy.sign_in_allowed?(user, :password)).to be(false)
  end

  it "does not turn passwordless mode into an email bypass for strict accounts" do
    user.add_auth_strict = true
    [true, false].each do |enabled|
      strict = policy(password_enabled: enabled)
      expect(strict.methods_for(user)).to eq([:passkey])
      expect(strict.recoverable?(user)).to be(false)
      expect(strict.fallback?(user)).to be(false)
    end
  end
end
