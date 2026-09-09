# frozen_string_literal: true

require "spec_helper"
require_relative "../support/microsoft_oidc_host"
require_relative "../support/mobile_provider_journey"

RSpec.describe "Microsoft OIDC installed-package browser acceptance" do
  before(:context) do
    @directory = Dir.mktmpdir("add-auth-microsoft-browser-")
    @fixture = MicrosoftOidcHost.new(@directory)
    @evidence = []
  end

  after do |example|
    if @fixture&.browser
      @evidence << {example: example.description, passed: example.exception.nil?, status: @fixture.status,
                    browser: @fixture.browser.capabilities.browser_version}
    end
  end

  after(:context) do
    File.write(ENV.fetch("ADD_AUTH_MICROSOFT_EVIDENCE"), JSON.pretty_generate(@evidence)) if ENV["ADD_AUTH_MICROSOFT_EVIDENCE"]
    @fixture&.close
    FileUtils.remove_entry(@directory) if @directory && !ENV["ADD_AUTH_KEEP_MICROSOFT_FIXTURE"]
  end

  include_examples "a provider browser-to-mobile handoff", [[true, true], [true, false], [false, false]].map { |js, turbo| {javascript: js, turbo: turbo} },
    {"fetch_site" => "cross-site", "method" => "GET", "status" => 303,
     "strategy" => "OmniAuth::Strategies::OpenIDConnect", "verified_uid" => "fixture-microsoft-pairwise-subject"}

  [[true, true], [true, false], [false, false]].each do |javascript, turbo|
    it "signs into the original UUID with Turbo #{turbo} and JavaScript #{javascript}, then rejects replay" do
      @fixture.start(javascript: javascript, turbo: turbo)
      result = @fixture.submit
      expect(result).to include("strategy_version" => "0.8.0", "user_type" => "uuid", "turbo" => turbo,
        "failure_handler_unchanged" => true, "validator_unchanged" => true, "methods_unchanged" => true,
        "owner_email" => "original-owner@example.test", "identity_owner" => "ac782247-7da0-4c52-903f-234fcc409640", "users_count" => 2)
      expect(result.fetch("sessions")).to eq([["ac782247-7da0-4c52-903f-234fcc409640", "external_identity"]])
      expect(result.fetch("consumed")).to eq(1)
      expect(result.fetch("key_reads")).to be_positive
      expect(result.fetch("userinfo_reads")).to eq(1)
      expect(result.fetch("callbacks").last).to include("status" => 303, "strategy" => "OmniAuth::Strategies::OpenIDConnect",
        "verified_uid" => "fixture-microsoft-pairwise-subject", "fetch_site" => "cross-site", "method" => "GET")
      expect(@fixture.browser.find_element(tag_name: "body").text).to include("Signed in UUID ac782247-7da0-4c52-903f-234fcc409640 through external_identity")
      replay = @fixture.replay
      expect(replay.fetch("sessions")).to eq(result.fetch("sessions"))
      expect(replay.fetch("consumed")).to eq(1)
      expect(replay.fetch("callbacks").last).to include("verified_uid" => nil, "status" => 302, "omniauth_error" => "Rack::OAuth2::Client::Error")
      expect(replay.fetch("exchanges").size).to eq(2)
      expect(@fixture.browser.find_element(tag_name: "body").text).to eq("Host OAuth failure landing")
    end
  end

  %w[state nonce issuer audience signature expired].each do |mode|
    it "rejects #{mode} through the real protocol library before granting Core authority" do
      @fixture.start(mode: mode)
      result = @fixture.submit
      expect(result.fetch("sessions")).to be_empty
      expect(result.fetch("consumed")).to eq(0)
      expect(result.fetch("callbacks").last.fetch("verified_uid")).to be_nil
      expect(result.fetch("exchanges").size).to eq((mode == "state") ? 0 : 1)
      expect(result).to include("failure_handler_unchanged" => true, "validator_unchanged" => true, "methods_unchanged" => true)
      expect(result.fetch("callbacks").last.fetch("status")).to eq(302)
      expected = {"nonce" => "OpenIDConnect::ResponseObject::IdToken::InvalidNonce",
                  "issuer" => "OpenIDConnect::ResponseObject::IdToken::InvalidIssuer",
                  "audience" => "OpenIDConnect::ResponseObject::IdToken::InvalidAudience",
                  "expired" => "OpenIDConnect::ResponseObject::IdToken::ExpiredToken",
                  "state" => "OmniAuth::Strategies::OpenIDConnect::CallbackError",
                  "signature" => "JSON::JWS::VerificationFailed"}.fetch(mode)
      expect(result.fetch("callbacks").last.fetch("omniauth_error")).to eq(expected)
      expect(@fixture.browser.find_element(tag_name: "body").text).to eq("Host OAuth failure landing")
    end
  end
end
