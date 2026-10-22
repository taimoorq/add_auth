# frozen_string_literal: true

RSpec.describe AddAuth::Core::Intake do
  let(:digest) do
    AddAuth::Core::Digest::Hmac.new(salt: "intake", secret: "s" * 32)
  end
  let(:normalizer) { ->(value) { value.to_s.strip.downcase } }
  let(:limiter) { ->(key:, limit:) { true } }

  def intake(challenge:, policy: :closed, bypasses: [])
    described_class.new(digest: digest, normalizer: normalizer, limiter: limiter,
      challenge: challenge, challenge_on: [:sign_in], challenge_when_unavailable: policy,
      on_challenge_unavailable: ->(action:) { bypasses << action })
  end

  it "fails closed when the provider is unavailable" do
    bypasses = []
    result = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :unavailable), bypasses: bypasses).call(
      identifier: "Person@example.test", ip: "192.0.2.1", action: :sign_in, challenge_token: "token"
    )

    expect(result).to eq(:challenge_unavailable)
    expect(bypasses).to be_empty
  end

  it "requires an explicit open policy to proceed during an outage and records it" do
    bypasses = []
    result = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :unavailable), policy: :open,
      bypasses: bypasses).call(identifier: "Person@example.test", ip: "192.0.2.1", action: :sign_in, challenge_token: "token")

    expect(result).to eq("person@example.test")
    expect(bypasses).to eq([:sign_in])
  end

  it "never opens the gate for a rejected or missing token" do
    challenge = AddAuth::Core::Challenge::Test.new(mode: :rejected)
    result = intake(challenge: challenge, policy: :open).call(
      identifier: "Person@example.test", ip: "192.0.2.1", action: :sign_in, challenge_token: nil
    )

    expect(result).to eq(:challenge_rejected)
  end

  context "with counting budgets" do
    let(:counts) { Hash.new(0) }
    let(:limiter) { ->(key:, limit:) { (counts[key] += 1) <= limit } }
    let(:identifier_key) { digest.digest("identifier:person@example.test:sign_in") }

    it "stops at an exhausted IP budget without charging the target identifier" do
      gate = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :success))
      30.times { gate.call(identifier: "other-#{_1}@example.test", ip: "198.51.100.9", action: :sign_in, challenge_token: "t") }
      expect(gate.call(identifier: "Person@example.test", ip: "198.51.100.9", action: :sign_in, challenge_token: "t")).to eq(:rate_limited)
      expect(counts[identifier_key]).to eq(0)
    end

    it "does not let rejected or unavailable challenges from many addresses lock out the target" do
      rejected = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :rejected))
      unavailable = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :unavailable))
      20.times do |index|
        expect(rejected.call(identifier: "Person@example.test", ip: "203.0.113.#{index}", action: :sign_in)).to eq(:challenge_rejected)
        expect(unavailable.call(identifier: "Person@example.test", ip: "203.0.114.#{index}", action: :sign_in, challenge_token: "t")).to eq(:challenge_unavailable)
      end
      expect(counts[identifier_key]).to eq(0)
      passed = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :success))
      expect(passed.call(identifier: "Person@example.test", ip: "192.0.2.50", action: :sign_in, challenge_token: "t")).to eq("person@example.test")
    end

    it "charges the identifier only after the challenge passes and still bounds verified attempts" do
      passed = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :success))
      5.times { |index| expect(passed.call(identifier: "Person@example.test", ip: "192.0.2.#{index}", action: :sign_in, challenge_token: "t")).to eq("person@example.test") }
      expect(passed.call(identifier: "Person@example.test", ip: "192.0.2.99", action: :sign_in, challenge_token: "t")).to eq(:rate_limited)
    end

    it "keeps a separate anonymous budget apart from the challenge action" do
      gate = intake(challenge: AddAuth::Core::Challenge::Null.new)
      31.times { gate.anonymous(ip: "192.0.2.1", action: :sign_in, budget: :passkey_options) }
      expect(gate.anonymous(ip: "192.0.2.1", action: :sign_in, budget: :passkey_options)).to eq(:rate_limited)
      expect(gate.anonymous(ip: "192.0.2.1", action: :sign_in)).to be(true)
    end
  end

  it "rejects an unknown outage policy" do
    expect {
      intake(challenge: AddAuth::Core::Challenge::Null.new, policy: :maybe)
    }.to raise_error(ArgumentError, /closed or :open/)
  end
end
