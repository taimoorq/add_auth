# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/remaining_factors"
require "add_auth/core/passwords/credential"
require "add_auth/core/passwords/bcrypt_support"
require "add_auth/core/passwords/legacy_bcrypt"

RSpec.describe AddAuth::Core::RemainingFactors do
  let(:user) { Struct.new(:email_address, :password_digest, :add_auth_strict, :add_auth_password_scheme).new("owner@example.test", "", false, nil) }
  let(:count) { 0 }
  let(:passwords) { true }
  let(:passkeys) { true }
  let(:email) { true }
  let(:address) { nil }
  let(:legacy) { nil }
  let(:current) { AddAuth::Core::Passwords::BcryptSupport.new }
  let(:password) { AddAuth::Core::Passwords::Credential.new(legacy_verifier: legacy) }
  let(:access) do
    AddAuth::Core::AccessPolicy.new(credentials: ->(_) {}, passkeys_enabled: passkeys, email_enabled: email,
      password_enabled: passwords, trusted_recovery_address: ->(_) { address })
  end
  subject(:remaining) do
    described_class.new(access_policy: access, passkey_count: ->(_) { count },
      password_available: ->(account) { password.available?(user: account, current: current) })
  end

  it "rejects enabled methods without actual credentials or trusted recovery" do
    expect(remaining.call(user)).to be(false)
  end

  [nil, false, true, "1", 1.0, -1, 0].each do |value|
    context "with invalid live count #{value.inspect}" do
      let(:count) { value }
      it("fails closed") { expect(remaining.call(user)).to be(false) }
    end
  end

  context "with a live passkey" do
    let(:count) { 1 }
    it("accepts the enrolled factor") { expect(remaining.call(user)).to be(true) }
    context "when disabled" do
      let(:passkeys) { false }
      it("does not count it") { expect(remaining.call(user)).to be(false) }
    end
    it "supports strict accounts only through an enabled live passkey" do
      user.add_auth_strict = true
      expect(remaining.call(user)).to be(true)
    end
  end

  context "with independently trusted recovery" do
    let(:address) { user.email_address }
    it("accepts the matching current address") { expect(remaining.call(user)).to be(true) }
    context "when email is disabled" do
      let(:email) { false }
      it("rejects the address") { expect(remaining.call(user)).to be(false) }
    end
    it "does not downgrade strict policy" do
      user.add_auth_strict = true
      expect(remaining.call(user)).to be(false)
    end
  end

  context "with a stale recovery address" do
    let(:address) { "previous@example.test" }
    it("rejects it") { expect(remaining.call(user)).to be(false) }
  end

  context "with a stock Rails bcrypt credential" do
    before { user.password_digest = BCrypt::Password.create("correct-password", cost: 4).to_s }
    it "accepts availability without running authentication or hashing" do
      expect(BCrypt::Engine).not_to receive(:hash_secret)
      expect(BCrypt::Password).not_to receive(:create)
      expect(password).not_to receive(:authenticate)
      expect(remaining.call(user)).to be(true)
    end
    context "when passwords are disabled" do
      let(:passwords) { false }
      it("rejects the password") { expect(remaining.call(user)).to be(false) }
    end
    it "rejects strict accounts despite a supported password" do
      user.add_auth_strict = true
      expect(remaining.call(user)).to be(false)
    end
    ["", "unknown", "argon2", "devise_bcrypt"].each do |scheme|
      it "does not infer support for #{scheme.inspect} from a bcrypt-shaped digest" do
        user.add_auth_password_scheme = scheme
        expect(remaining.call(user)).to be(false)
      end
    end
    it "never falls back to the current verifier for an unknown profile" do
      user.add_auth_password_scheme = "unknown"
      expect(current).not_to receive(:available?)
      expect(remaining.call(user)).to be(false)
      expect(password.authenticate(user: user, password: "correct-password", current: ->(_) { raise "must not be called" })).to be_failure
    end
  end

  context "with an explicit legacy verifier" do
    let(:legacy) { AddAuth::Core::Passwords::LegacyBcrypt.new(pepper: -> { "host-secret" }, maximum_cost: 4) }
    before do
      user.password_digest = BCrypt::Password.create("correct-passwordhost-secret", cost: 4).to_s
      user.add_auth_password_scheme = "devise_bcrypt"
    end
    it "uses the selected adapter for metadata and authentication without fallback" do
      expect(current).not_to receive(:available?)
      expect(remaining.call(user)).to be(true)
      expect(password.authenticate(user: user, password: "correct-password", current: ->(_) { raise "wrong verifier" })).to be_success
      expect(password.authenticate(user: user, password: "wrong", current: ->(_) { raise "wrong verifier" })).to be_failure
    end
    it "rejects costs above the configured verifier's bound without hashing" do
      user.password_digest = user.password_digest.sub("$04$", "$05$")
      expect(BCrypt::Engine).not_to receive(:hash_secret)
      expect(remaining.call(user)).to be(false)
    end
    context "with unavailable pepper configuration" do
      let(:legacy) { AddAuth::Core::Passwords::LegacyBcrypt.new(pepper: -> { false }) }
      it("fails closed") { expect(remaining.call(user)).to be(false) }
    end
    context "with an older verifier lacking availability support" do
      let(:legacy) { double(verify: true) }
      it("does not count method presence as support") { expect(remaining.call(user)).to be(false) }
    end
  end

  context "with an explicitly configured override current verifier" do
    let(:current) do
      Class.new {
        def available?(digest:) = digest == "override-format:v1"
        def verify(digest:, password:) = available?(digest: digest) && password == "override-secret"
      }.new
    end
    it "preserves the host adapter instead of requiring bcrypt" do
      user.password_digest = "override-format:v1"
      user.add_auth_password_scheme = "rails"
      expect(remaining.call(user)).to be(true)
      expect(password.authenticate(user: user, password: "override-secret",
        current: ->(value) { current.verify(digest: user.password_digest, password: value) })).to be_success
      user.password_digest = "unsupported-format:v2"
      expect(remaining.call(user)).to be(false)
    end
    it "requires an exact true support result" do
      user.password_digest = "override-format:v1"
      allow(current).to receive(:available?).and_return("yes")
      expect(remaining.call(user)).to be(false)
    end
  end
end

RSpec.describe AddAuth::Core::Passwords::BcryptSupport do
  it "rejects absent, malformed, unsupported and invalid-encoding digests without hashing" do
    support = described_class.new
    valid = BCrypt::Password.create("stock-password", cost: 4).to_s
    expect(BCrypt::Engine).not_to receive(:hash_secret)
    [nil, "", "not-a-password", valid + "\n", valid.sub("$2a$", "$2x$"), valid.sub("$04$", "$03$"),
      valid.sub("$04$", "$32$"), "\xff".dup.force_encoding("UTF-8")].each do |digest|
      expect(support.available?(digest: digest)).to be(false)
    end
    expect(support.available?(digest: valid)).to be(true)
  end

  it "supports stock Rails models without migration metadata" do
    user = Struct.new(:password_digest).new(BCrypt::Password.create("stock-password", cost: 4).to_s)
    selector = AddAuth::Core::Passwords::Credential.new(legacy_verifier: nil)
    expect(selector.available?(user: user, current: described_class.new)).to be(true)
    expect(selector.authenticate(user: user, password: "stock-password", current: ->(value) {
      BCrypt::Password.new(user.password_digest).is_password?(value)
    })).to be_success
  end
end
