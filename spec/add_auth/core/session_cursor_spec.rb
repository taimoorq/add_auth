# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/session_key"
require "add_auth/core/session_cursor"

RSpec.describe AddAuth::Core::SessionCursor do
  %i[integer uuid].each do |type|
    context "with #{type} IDs" do
      let(:key) { AddAuth::Core::SessionKey.new(type: type) }
      let(:cursor) { described_class.new(key: key) }
      let(:id) { (type == :uuid) ? "ac782247-7da0-4c52-903f-234fcc409640" : 42 }
      let(:time) { Time.utc(2026, 9, 18, 10, 15, 30, 123456) }

      it "round-trips microseconds and the typed tie breaker" do
        row = Struct.new(:id, :created_at).new(id, time)
        expect(cursor.decode(cursor.encode(row))).to eq(created_at: time, id: id)
      end

      it "rejects malformed, oversized, impossible-date and wrong-type cursors" do
        invalid = [nil, {}, [], "", "-1", "9" * 100, "sc2:e30", "sc1:%%%", "sc1:" + "a" * 300, "\xff".b]
        invalid += [[], [time.iso8601(6)], [time.iso8601(6), {}], ["2026-02-31T00:00:00.000000Z", id],
          ["0000-01-01T00:00:00.000000Z", id],
          [time.iso8601(6), (type == :uuid) ? 42 : SecureRandom.uuid], [time.iso8601(6), id, "extra"]].map do |fields|
          "sc1:" + Base64.urlsafe_encode64(JSON.generate(fields), padding: false)
        end
        invalid.each { |value| expect(cursor.decode(value)).to be_nil }
      end

      it "accepts legacy numeric navigation only for integer schemas" do
        expect(cursor.decode("42")).to eq((type == :integer) ? {legacy_id: 42} : nil)
      end
    end
  end
end

RSpec.describe AddAuth::Core::SessionKey do
  it "does not coerce UUIDs, numeric prefixes, out-of-range integers or objects into integer IDs" do
    key = described_class.new(type: :integer)
    expect(key.parse("42")).to eq(42)
    expect(key.parse(42)).to eq(42)
    [SecureRandom.uuid, "42x", "042", -1, 0, 2**63, (2**63).to_s, 4.2, {}, :"42", "\xff".b].each do |id|
      expect(key.parse(id)).to be_nil
    end
    expect(key.legacy("42")).to be_nil
    expect(key.legacy(42)).to eq(42)
  end

  it "accepts canonical UUIDs without imposing a UUID version" do
    key = described_class.new(type: :uuid)
    uuid = "abcdef01-1234-7234-abcd-123456789012"
    expect(key.parse(uuid.upcase)).to eq(uuid)
    expect(key.legacy(uuid)).to eq(uuid)
    [42, "42", uuid.delete("-"), "#{uuid}suffix", {}, "\xff".b].each { |id| expect(key.parse(id)).to be_nil }
  end

  it "refuses unsupported store key types" do
    expect { described_class.new(type: :string) }.to raise_error(ArgumentError, /key type/)
  end
end
