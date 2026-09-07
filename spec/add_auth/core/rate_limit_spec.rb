# frozen_string_literal: true

RSpec.describe AddAuth::Core::RateLimit do
  let(:clock) { double(now: Time.at(0)) }
  let(:counts) { Hash.new(0) }
  let(:counter) { ->(key:, expires_in:) { counts[key] += 1 } }
  subject(:limiter) { described_class.new(counter: counter, clock: clock) }

  it "does not reset the budget across any of the staggered boundaries" do
    (0...360).each do |second|
      counts.clear
      allow(clock).to receive(:now).and_return(Time.at(second))
      5.times { expect(limiter.call(key: "account", limit: 5)).to be(true) }
      allow(clock).to receive(:now).and_return(Time.at(second + 299))
      expect(limiter.call(key: "account", limit: 5)).to be(false), "burst starting at #{second}"
    end
  end

  it "admits again after at most six quiet minutes and keeps independent keys" do
    5.times { expect(limiter.call(key: "account", limit: 5)).to be(true) }
    expect(limiter.call(key: "another-account", limit: 5)).to be(true)
    allow(clock).to receive(:now).and_return(Time.at(360))
    expect(limiter.call(key: "account", limit: 5)).to be(true)
  end

  it "requires positive integer counter receipts instead of accepting a broken store" do
    [nil, false, "1", 0, -1].each do |receipt|
      invalid = described_class.new(counter: ->(**) { receipt })
      expect { invalid.call(key: "account", limit: 5) }.to raise_error(AddAuth::Error, /atomic increment/)
    end
  end
end
