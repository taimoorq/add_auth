# frozen_string_literal: true

RSpec.describe AddAuth::Configuration do
  subject(:configuration) { described_class.new }

  it "defaults to no configured challenge and closed outage policy" do
    expect(configuration.challenge.verify(token: nil, remote_ip: nil, action: :sign_in)).to be_success
    expect(configuration.challenge_on).to eq([])
    expect(configuration.challenge_when_unavailable).to eq(:closed)
  end

  it "requires explicit key material outside the Rails adapter" do
    expect { configuration.session_token_digest }.to raise_error(AddAuth::Error, /digest_secret/)
  end

  it "separates token purposes with the same injected base secret" do
    configuration.digest_secret = -> { "s" * 32 }
    expect(configuration.session_token_digest.digest("token"))
      .not_to eq(configuration.sign_in_token_digest.digest("token"))
  end

  it "uses a host override without consulting the default secret provider" do
    override = AddAuth::Core::Digest::Hmac.new(salt: "custom", secret: "x" * 32)
    configuration.session_token_digest = override
    expect(configuration.session_token_digest.matches?(override.digest("token"), "token")).to be(true)
  end

  it "accepts only explicit challenge outage policies" do
    configuration.challenge_when_unavailable = :open
    expect(configuration.challenge_when_unavailable).to eq(:open)
    expect { configuration.challenge_when_unavailable = :bypass }.to raise_error(ArgumentError, /closed or :open/)
  end

  it "loads the commented Rails reference without changing defaults or enabling features" do
    config = described_class.new
    original = described_class.new
    template = File.expand_path("../../lib/generators/add_auth/install/templates/initializer.rb", __dir__)
    source = File.read(template)
    allow(AddAuth).to receive(:configure).and_yield(config)
    load template
    described_class.instance_methods(false).grep(/=\z/).each do |writer|
      expect(source).to match(/^\s*(?:# )?config\.#{Regexp.escape(writer.to_s.delete_suffix("="))} =/)
    end
    %i[session lifecycle step_up email_link passkeys notifications mobile maintenance].each do |section|
      actual = config.public_send(section)
      expected = original.public_send(section)
      expected.each_pair do |key, value|
        expect(source).to match(/^\s+config\.#{section}\.#{key} =/)
        next if value.is_a?(Proc)
        expect(actual.public_send(key)).to eq(value), "#{section}.#{key} changed its default"
      end
    end
    %i[passwords_enabled turbo_enabled base_url mail_from stylesheet css_classes rate_limit_store
      support_url legacy_password_verifier challenge_on challenge_when_unavailable].each do |setting|
      expect(config.public_send(setting)).to eq(original.public_send(setting))
    end
    expect(config.external_identities.enabled).to be(false)
    expect(config.lifecycle.password_policy.call("short")).to be(false)
    expect(config.lifecycle.password_policy.call("correct-password")).to be(true)
    expect(config.trusted_recovery_address.call(Object.new)).to be_nil
    expect(config.lifecycle.profile_attributes.call({role: "admin"})).to eq({})
    expect(config.lifecycle.provision.call(Object.new)).to be_nil
  end
end
