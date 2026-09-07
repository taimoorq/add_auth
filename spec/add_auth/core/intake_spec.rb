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
    result = intake(challenge: AddAuth::Core::Challenge::Test.new(mode: :unavailable)).call(
      identifier: "Person@example.test", ip: "192.0.2.1", action: :sign_in, challenge_token: "token"
    )

    expect(result).to eq(:challenge_unavailable)
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

  it "rejects an unknown outage policy" do
    expect {
      intake(challenge: AddAuth::Core::Challenge::Null.new, policy: :maybe)
    }.to raise_error(ArgumentError, /closed or :open/)
  end
end
