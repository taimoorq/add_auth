# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/mobile_authentication"

RSpec.describe AddAuth::Core::MobileProfile do
  let(:attributes) { {lifetime: 30 * 86_400, idle_timeout: 14 * 86_400, clients: %w[android ios]} }
  subject(:profile) { described_class.new(**attributes) }

  it "requires finite host-selected lifetimes and exact registered clients" do
    expect(profile.client?("android")).to be(true)
    [nil, :android, "ANDROID", {}, "unknown"].each { |id| expect(profile.client?(id)).to be(false) }
    expect(profile.bearer).to match(described_class::PATTERN)
    expect(profile.bearer).not_to match(AddAuth::Core::Sessions::PATTERN)
    expect(profile.clients).to be_frozen
    [nil, 0, -1, 90 * 86_400 + 1, Float::INFINITY, 100.1].each do |value|
      expect { described_class.new(**attributes.merge(lifetime: value)) }.to raise_error(ArgumentError)
      expect { described_class.new(**attributes.merge(idle_timeout: value)) }.to raise_error(ArgumentError)
    end
    expect { described_class.new(**attributes.merge(lifetime: 60, idle_timeout: 61)) }.to raise_error(ArgumentError)
  end

  it "rejects unbounded, duplicate or malformed client configuration" do
    [nil, [], ["a"] * 2, ["a\n"], ["a" * 65], [1], 33.times.map { |i| "client#{i}" }].each do |clients|
      expect { described_class.new(**attributes.merge(clients: clients)) }.to raise_error(ArgumentError)
    end
  end

  it "registers exact HTTPS or private-scheme callbacks without accepting an open redirect" do
    callback = "com.example.app://auth/callback"
    configured = described_class.new(**attributes, callbacks: {"ios" => callback})
    expect(configured.callback("ios")).to eq(callback)
    ["http://example.test/callback", "https://user:pass@example.test/callback", "https://example.test/callback?next=elsewhere",
      "https://example.test/callback#fragment", "https://example.test/%2fcallback", "https://example.test/\\callback", "javascript:alert(1)"].each do |uri|
      expect { described_class.new(**attributes, callbacks: {"ios" => uri}) }.to raise_error(ArgumentError)
    end
    expect { described_class.new(**attributes, callbacks: {"unknown" => callback}) }.to raise_error(ArgumentError)
  end

  it "accepts one exact Authorization credential without alternate token transports" do
    parser = AddAuth::Core::MobileAuthentication
    raw = profile.bearer
    expect(parser.bearer("Bearer #{raw}")).to eq(raw)
    expect(parser.bearer("bearer #{raw}")).to eq(raw)
    [nil, {}, raw, "Bearer #{raw}, Bearer #{raw}", "Bearer  #{raw}", "Bearer\t#{raw}",
      "Bearer #{raw}\n", "Basic #{raw}", "Bearer #{raw.sub("am1:", "lk1:")}", "Bearer #{raw.sub("am1:", "AM1:")}"]
      .each { |header| expect(parser.bearer(header)).to be_nil }
  end
end
