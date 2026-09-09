# frozen_string_literal: true

require "spec_helper"
require_relative "../support/apple_form_post_host"
require_relative "../support/mobile_provider_journey"

RSpec.describe "Apple HTTPS cross-site form_post browser acceptance" do
  before(:context) do
    @directory = Dir.mktmpdir("add-auth-apple-https-")
    @fixture = AppleFormPostHost.new(@directory)
    @evidence = []
  end

  after do |example|
    if @fixture&.browser
      @evidence << {example: example.description, passed: example.exception.nil?, status: @fixture.status,
                    browser: @fixture.browser.capabilities.browser_version,
                    start_cookies: @fixture.start_cookies, cookies: @fixture.cookies.map { |cookie| cookie.except("value") }}
    end
  end

  after(:context) do
    File.write(ENV.fetch("ADD_AUTH_APPLE_EVIDENCE"), JSON.pretty_generate(@evidence)) if ENV["ADD_AUTH_APPLE_EVIDENCE"]
    @fixture&.close
    FileUtils.remove_entry(@directory) if @directory && !ENV["ADD_AUTH_KEEP_APPLE_FIXTURE"]
  end

  include_examples "a provider browser-to-mobile handoff", %w[turbo html no_js].map { |mode| {browser_mode: mode} },
    {"cookies" => ["add_auth_apple_callback"], "fetch_site" => "cross-site", "method" => "POST", "status" => 303,
     "strategy" => "OmniAuth::Strategies::Apple", "verified_uid" => "fixture-apple-subject"}

  it "omits the explicit Lax session cookie, sends only scoped correlation, finalizes Core and rejects replay" do
    @fixture.start
    cookies = @fixture.cookies
    normal = cookies.find { |cookie| cookie["name"] == "_apple_https_fixture" }
    capsule = cookies.find { |cookie| cookie["name"] == "add_auth_apple_callback" }
    expect(normal).to include("sameSite" => "Lax", "secure" => true, "httpOnly" => true, "path" => "/")
    expect(capsule).to include("sameSite" => "None", "secure" => true, "httpOnly" => true, "path" => "/auth/apple/callback")
    expect(capsule.fetch("value")).not_to include("fixture-apple-subject", "transaction", "browser_secret")
    result = @fixture.submit
    expect(result.fetch("callbacks").last).to include("cookies" => ["add_auth_apple_callback"], "fetch_site" => "cross-site", "method" => "POST", "status" => 303,
      "strategy" => "OmniAuth::Strategies::Apple", "verified_uid" => "fixture-apple-subject")
    expect(result.fetch("strategy_version")).to eq("1.4.0")
    expect(result.fetch("sessions")).to eq(["external_identity"])
    expect(result.fetch("consumed")).to eq(1)
    expect(result.fetch("keys_reads")).to be_positive
    expect(result.fetch("exchanges").last).to include("grant_type" => "authorization_code", "client_id" => "fixture-apple-client",
      "redirect_uri" => "#{@fixture.origin}/auth/apple/callback")
    expect(@fixture.browser.find_element(tag_name: "body").text).to include("Signed in as apple-owner@example.test through external_identity")
    expect(@fixture.cookies.none? { |cookie| cookie["name"] == "add_auth_apple_callback" }).to be(true)
    replay = @fixture.replay
    expect(replay.fetch("callbacks").last).to include("status" => 422, "fetch_site" => "cross-site", "cookies" => ["add_auth_apple_callback"])
    expect(replay.fetch("sessions")).to eq(["external_identity"])
    expect(replay.fetch("consumed")).to eq(1)
  end

  %w[state nonce signature issuer audience issued_at expired].each do |mode|
    it "rejects mismatched #{mode} through the actual strategy without Core authority" do
      @fixture.start(mode: mode)
      result = @fixture.submit
      expect(result.fetch("callbacks").last).to include("status" => 422, "fetch_site" => "cross-site", "cookies" => ["add_auth_apple_callback"])
      expect(result.fetch("callbacks").last.fetch("strategy")).to eq("OmniAuth::Strategies::Apple")
      expect(result.fetch("exchanges").size).to eq((mode == "state") ? 0 : 1)
      expect(result.fetch("sessions")).to be_empty
      expect(result.fetch("consumed")).to eq(0)
      expect(@fixture.browser.find_element(tag_name: "body").text).to include("Apple strategy rejected callback")
    end
  end

  %w[html no_js].each do |mode|
    it "completes the real cross-site callback with #{mode}" do
      @fixture.start(browser_mode: mode)
      result = @fixture.submit
      expect(result.fetch("callbacks").last).to include("cookies" => ["add_auth_apple_callback"], "fetch_site" => "cross-site", "status" => 303)
      expect(result.fetch("sessions")).to eq(["external_identity"])
      expect(result.fetch("consumed")).to eq(1)
      expect(@fixture.browser.find_element(tag_name: "body").text).to include("Signed in as apple-owner@example.test")
    end
  end
end
