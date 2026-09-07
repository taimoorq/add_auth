# frozen_string_literal: true

RSpec.describe Latchkey::Core::Challenge do
  describe Latchkey::Core::Challenge::Null do
    it "always succeeds and exposes no site key" do
      verification = subject.verify(token: nil, remote_ip: nil, action: :sign_in)

      expect(verification).to be_success
      expect(subject.site_key).to be_nil
    end
  end

  describe Latchkey::Core::Challenge::Test do
    it "succeeds, rejects, or reports unavailable per its configured mode" do
      expect(described_class.new(mode: :success).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)).to be_success
      expect(described_class.new(mode: :rejected).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)).to be_rejected
      expect(described_class.new(mode: :unavailable).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)).to be_unavailable
    end

    it "rejects an unknown mode rather than silently succeeding" do
      expect {
        described_class.new(mode: :bogus).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)
      }.to raise_error(ArgumentError, /unknown Test challenge mode/)
    end
  end
  it "keeps challenge outcomes closed and immutable" do
    type = described_class::Base::Verification
    expect { type.new(status: :unknown) }.to raise_error(ArgumentError)
    result = type.new(status: :success)
    expect(result).to be_frozen
    expect { result.status = :unavailable }.to raise_error(NoMethodError)
  end

  describe Latchkey::Core::Challenge::Turnstile do
    let(:calls) { [] }
    let(:transport) do
      lambda do |uri:, params:|
        calls << [uri, params]
        [200, JSON.generate("success" => true, "action" => "sign_in", "hostname" => "accounts.example.test")]
      end
    end

    subject(:provider) do
      described_class.new(site_key: "site", secret_key: "secret", allowed_hostnames: ["accounts.example.test"],
        transport: transport)
    end

    it "verifies a token, binds the action and checks the configured hostname" do
      result = provider.verify(token: "token", remote_ip: "192.0.2.1", action: :sign_in)

      expect(result).to be_success
      expect(calls.fetch(0).first.to_s).to eq("https://challenges.cloudflare.com/turnstile/v0/siteverify")
      expect(calls.fetch(0).last).to include("secret" => "secret", "response" => "token", "remoteip" => "192.0.2.1")
      expect(provider.site_key).to eq("site")
      expect(provider.script_url).to include("challenges.cloudflare.com")
    end

    it "rejects missing and oversized tokens without calling the provider" do
      expect(provider.verify(token: nil, remote_ip: nil, action: :sign_in)).to be_rejected
      expect(provider.verify(token: "x" * 2_049, remote_ip: nil, action: :sign_in)).to be_rejected
      expect(calls).to be_empty
    end

    it "rejects a failed provider response, action mismatch and hostname mismatch" do
      failed = described_class.new(site_key: "site", secret_key: "secret",
        transport: ->(**) { [200, JSON.generate("success" => false)] })
      mismatch = described_class.new(site_key: "site", secret_key: "secret",
        transport: ->(**) { [200, JSON.generate("success" => true, "action" => "email_link")] })
      wrong_host = described_class.new(site_key: "site", secret_key: "secret", allowed_hostnames: ["accounts.example.test"],
        transport: ->(**) { [200, JSON.generate("success" => true, "action" => "sign_in", "hostname" => "evil.example")] })

      expect(failed.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_rejected
      expect(mismatch.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_rejected
      expect(wrong_host.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_rejected
    end

    it "reports provider outages and malformed responses as unavailable" do
      down = described_class.new(site_key: "site", secret_key: "secret",
        transport: ->(**) { [503, "retry later"] })
      malformed = described_class.new(site_key: "site", secret_key: "secret",
        transport: ->(**) { [200, "not-json"] })

      expect(down.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_unavailable
      expect(malformed.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_unavailable
    end

    it "requires secure provider endpoints and bounded timeouts" do
      expect { described_class.new(site_key: "site", secret_key: "secret", endpoint: "http://localhost/verify") }
        .to raise_error(ArgumentError, /HTTPS/)
      expect { described_class.new(site_key: "site", secret_key: "secret", endpoint: "https://evil.example/verify") }
        .to raise_error(ArgumentError, /host is not allowed/)
      expect { described_class.new(site_key: "site", secret_key: "secret", open_timeout: 0) }
        .to raise_error(ArgumentError, /open_timeout/)
    end
  end

  describe Latchkey::Core::Challenge::Recaptcha do
    it "enforces action, hostname and score for v3" do
      provider = described_class.new(site_key: "site", secret_key: "secret", allowed_hostnames: "accounts.example.test",
        minimum_score: 0.7, transport: ->(**) {
          [200, JSON.generate("success" => true, "hostname" => "ACCOUNTS.EXAMPLE.TEST", "action" => "sign_in", "score" => 0.8)]
        })

      expect(provider.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_success
      expect(provider.version).to eq(:v3)
      expect(provider.minimum_score).to eq(0.7)
    end

    it "rejects v3 responses below the score or with the wrong action" do
      low_score = described_class.new(site_key: "site", secret_key: "secret", minimum_score: 0.7,
        transport: ->(**) { [200, JSON.generate("success" => true, "action" => "sign_in", "score" => 0.6)] })
      wrong_action = described_class.new(site_key: "site", secret_key: "secret", expected_action: "account_recovery",
        transport: ->(**) { [200, JSON.generate("success" => true, "action" => "sign_in", "score" => 0.9)] })

      expect(low_score.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_rejected
      expect(wrong_action.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_rejected
    end

    it "keeps v2 independent from v3-only action and score fields" do
      provider = described_class.new(site_key: "site", secret_key: "secret", version: :v2,
        allowed_hostnames: ["accounts.example.test"], transport: ->(**) {
          [200, JSON.generate("success" => true, "hostname" => "accounts.example.test")]
        })

      expect(provider.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_success
      expect(provider.stimulus_controller).to eq("latchkey--challenge-recaptcha")
    end

    it "validates constructor policy values" do
      expect { described_class.new(site_key: "site", secret_key: "secret", version: :v1) }
        .to raise_error(ArgumentError, /version/)
      expect { described_class.new(site_key: "site", secret_key: "secret", minimum_score: 2) }
        .to raise_error(ArgumentError, /minimum_score/)
    end
  end
end
