# frozen_string_literal: true

RSpec.describe Latchkey::Core::Digest::Hmac do
  subject(:adapter) { described_class.new(salt: "test", secret: "s" * 32) }

  it "matches an independent known OpenSSL computation" do
    key = OpenSSL::HMAC.digest("SHA256", "s" * 32, "test")
    expect(adapter.digest("token")).to eq(OpenSSL::HMAC.hexdigest("SHA256", key, "token"))
    expect(adapter.matches?(adapter.digest("token"), "token")).to be(true)
    expect(adapter.matches?(adapter.digest("other"), "token")).to be(false)
  end

  it "separates purposes and keys" do
    [described_class.new(salt: "other", secret: "s" * 32),
      described_class.new(salt: "test", secret: "x" * 32)].each do |other|
      expect(other.digest("token")).not_to eq(adapter.digest("token"))
    end
  end

  it "rejects missing, empty and short secrets" do
    [nil, "", "short", 32].each do |secret|
      expect { described_class.new(salt: "test", secret: secret) }.to raise_error(ArgumentError)
    end
  end

  it "rejects invalid salts and never coerces client values into secrets" do
    [nil, "", " ", 1].each do |salt|
      expect { described_class.new(salt: salt, secret: "s" * 32) }.to raise_error(ArgumentError)
    end
    [nil, "", [], {}, 1].each do |token|
      expect { adapter.digest(token) }.to raise_error(ArgumentError)
      expect(adapter.matches?(adapter.digest("valid"), token)).to be(false)
    end
  end

  it "snapshots key material and redacts inspection" do
    secret = "s" * 32
    salt = +"test"
    instance = described_class.new(salt: salt, secret: secret)
    before = instance.digest("token")
    secret.replace("x" * 32)
    salt.replace("changed")
    expect(instance.digest("token")).to eq(before)
    expect(instance.inspect).to include("FILTERED")
  end
end
