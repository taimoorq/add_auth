# frozen_string_literal: true

require "spec_helper"
require "webmock/rspec"
WebMock.disable_net_connect!(allow_localhost: true)

RSpec.describe "Provider protocol audit" do
  it "A13 classifies a provider internal error as unavailable" do
    provider = Latchkey::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "audit-secret",
      transport: ->(**_) { [200, JSON.generate(:success => false, "error-codes" => ["internal-error"])] })
    expect(provider.verify(token: "audit-token", remote_ip: nil, action: :sign_in)).to be_unavailable
  end

  it "A14 redacts provider secrets from inspection" do
    provider = Latchkey::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "audit-secret")
    expect(provider.inspect).not_to include("audit-secret")
  end

  it "A15 rejects malformed reCAPTCHA scores outside the provider range" do
    provider = Latchkey::Core::Challenge::Recaptcha.new(site_key: "site", secret_key: "audit-secret",
      transport: ->(**_) { [200, JSON.generate(success: true, action: "sign_in", score: 5.0, hostname: "example.test")] })
    expect(provider.verify(token: "audit-token", remote_ip: nil, action: :sign_in)).to be_rejected
  end

  it "A16 exercises the real HTTPS request path through WebMock" do
    request = stub_request(:post, "https://challenges.cloudflare.com/turnstile/v0/siteverify")
      .with(body: {"secret" => "audit-secret", "response" => "audit-token", "remoteip" => "192.0.2.1"})
      .to_return(status: 200, body: JSON.generate(success: true, action: "sign_in", hostname: "example.test"))
    provider = Latchkey::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "audit-secret", allowed_hostnames: ["example.test"])
    expect(provider.verify(token: "audit-token", remote_ip: "192.0.2.1", action: :sign_in)).to be_success
    expect(request).to have_been_requested.once
  end

  it "A17 fails closed without retry on a real transport timeout" do
    request = stub_request(:post, "https://challenges.cloudflare.com/turnstile/v0/siteverify").to_timeout
    provider = Latchkey::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "audit-secret")
    expect(provider.verify(token: "audit-token", remote_ip: nil, action: :sign_in)).to be_unavailable
    expect(request).to have_been_requested.once
  end
end

RSpec.describe Latchkey::Core::Challenge::Http do
  let(:endpoint) { "https://challenges.cloudflare.com/turnstile/v0/siteverify" }
  let(:http) { described_class.new(endpoint: endpoint, secret_key: "synthetic-provider-secret") }

  it "bounds real transport response size and nesting without leaking secrets" do
    ["x" * (described_class::MAX_RESPONSE_BYTES + 1), "[" * 12 + "0" + "]" * 12].each do |body|
      stub_request(:post, endpoint).to_return(status: 200, body: body)
      expect(http.call(token: "synthetic-token").status).to eq(:unavailable)
    end
    expect(http.inspect).not_to include("synthetic-provider-secret")
  end

  it "does not follow redirects or retry non-success responses" do
    request = stub_request(:post, endpoint).to_return(status: 302, headers: {"Location" => "https://example.test/collect"})
    expect(http.call(token: "synthetic-token").status).to eq(:unavailable)
    expect(request).to have_been_requested.once
    expect(a_request(:any, "https://example.test/collect")).not_to have_been_made
  end
end

RSpec.describe "Strict provider payloads" do
  it "distinguishes user failure from provider/configuration failure" do
    %w[internal-error invalid-input-secret missing-input-secret bad-request timeout-or-duplicate invalid-input-response].each do |code|
      provider = Latchkey::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "secret",
        transport: ->(**) { [200, JSON.generate(:success => false, "error-codes" => [code])] })
      result = provider.verify(token: "token", remote_ip: nil, action: :sign_in)
      expect(result.status).to eq(%w[timeout-or-duplicate invalid-input-response].include?(code) ? :rejected : :unavailable)
    end
  end

  it "requires a finite numeric score in range and mode-correct script URLs" do
    [-1, 1.1, "0.9", nil, true].each do |score|
      provider = Latchkey::Core::Challenge::Recaptcha.new(site_key: "site", secret_key: "secret",
        transport: ->(**) { [200, JSON.generate(success: true, hostname: "example.test", action: "sign_in", score: score)] })
      expect(provider.verify(token: "token", remote_ip: nil, action: :sign_in)).to be_rejected
      expect(provider.script_url).to end_with("?render=site")
    end
    v2 = Latchkey::Core::Challenge::Recaptcha.new(site_key: "site", secret_key: "secret", version: :v2)
    expect(v2.script_url).to end_with("?render=explicit")
  end
end
