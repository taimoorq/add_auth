# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/passwords/legacy_bcrypt"
require "add_auth/core/passwords/credential"

RSpec.describe AddAuth::Core::Passwords::LegacyBcrypt do
  subject(:verifier) { described_class.new(pepper: -> { pepper }) }
  let(:pepper) { nil }
  let(:password) { "original-password" }
  let(:digest) { BCrypt::Password.create("#{password}#{pepper}", cost: 4).to_s }

  it "verifies the exact submitted bytes and rejects a wrong password" do
    expect(verifier.verify(digest: digest, password: password)).to be(true)
    expect(verifier.verify(digest: digest, password: "wrong")).to be(false)
    expect(verifier.verify(digest: digest, password: " #{password}")).to be(false)
  end

  context "with a source pepper" do
    let(:pepper) { "legacy-secret" }
    it "requires the configured source verifier" do
      expect(verifier.verify(digest: digest, password: password)).to be(true)
      expect(described_class.new.verify(digest: digest, password: password)).to be(false)
      expect(verifier.inspect).not_to include(pepper)
    end
  end

  it "bounds malformed credentials and cost before performing expensive work" do
    expect(BCrypt::Password).not_to receive(:new)
    [nil, "", "broken", "$2a$31$#{"a" * 53}"].each do |value|
      expect(verifier.verify(digest: value, password: password)).to be(false)
    end
  end

  it "rejects nil, empty, excessive and invalidly encoded input" do
    [nil, "", "x" * 1025, "\xff".dup.force_encoding("UTF-8"), [], {}].each do |value|
      expect(verifier.verify(digest: digest, password: value)).to be(false)
    end
  end

  it "retains legacy bcrypt byte semantics without normalizing Unicode" do
    %W[#{"é" * 40} #{"a" * 100}].each do |value|
      stored = BCrypt::Password.create(value, cost: 4).to_s
      expect(verifier.verify(digest: stored, password: value)).to be(true)
    end
  end
end

RSpec.describe AddAuth::Core::Passwords::Credential do
  let(:user) { Struct.new(:password_digest, :add_auth_password_scheme).new("opaque", "devise_bcrypt") }
  let(:legacy) { double(verify: true) }
  subject(:credential) { described_class.new(legacy_verifier: legacy) }

  it "allows a deliberate override and never tries the current verifier for legacy credentials" do
    result = credential.authenticate(user: user, password: "original", current: ->(*) { raise "wrong verifier" })
    expect(result).to be_success
    expect(legacy).to have_received(:verify).with(digest: "opaque", password: "original")
  end

  it "does not fall back to a retired password after current verification fails" do
    user.add_auth_password_scheme = "rails"
    expect(legacy).not_to receive(:verify)
    expect(credential.authenticate(user: user, password: "old", current: ->(*) { false }).reason).to eq(:invalid_credentials)
  end

  it "fails closed for unknown profiles and missing adapters" do
    user.add_auth_password_scheme = "unknown"
    expect(credential.authenticate(user: user, password: "old", current: ->(*) { true }).reason).to eq(:invalid_credentials)
    user.add_auth_password_scheme = "devise_bcrypt"
    expect(described_class.new(legacy_verifier: nil).authenticate(user: user, password: "old", current: ->(*) { true })).to be_failure
  end
end
