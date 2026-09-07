# frozen_string_literal: true

RSpec.describe Latchkey::Configuration do
  subject(:configuration) { described_class.new }

  it "defaults to no configured challenge and closed outage policy" do
    expect(configuration.challenge.verify(token: nil, remote_ip: nil, action: :sign_in)).to be_success
    expect(configuration.challenge_on).to eq([])
    expect(configuration.challenge_when_unavailable).to eq(:closed)
  end

  it "requires explicit key material outside the Rails adapter" do
    expect { configuration.session_token_digest }.to raise_error(Latchkey::Error, /digest_secret/)
  end

  it "separates token purposes with the same injected base secret" do
    configuration.digest_secret = -> { "s" * 32 }
    expect(configuration.session_token_digest.digest("token"))
      .not_to eq(configuration.sign_in_token_digest.digest("token"))
  end

  it "uses a host override without consulting the default secret provider" do
    override = Latchkey::Core::Digest::Hmac.new(salt: "custom", secret: "x" * 32)
    configuration.session_token_digest = override
    expect(configuration.session_token_digest.matches?(override.digest("token"), "token")).to be(true)
  end

  it "accepts only explicit challenge outage policies" do
    configuration.challenge_when_unavailable = :open
    expect(configuration.challenge_when_unavailable).to eq(:open)
    expect { configuration.challenge_when_unavailable = :bypass }.to raise_error(ArgumentError, /closed or :open/)
  end
end
