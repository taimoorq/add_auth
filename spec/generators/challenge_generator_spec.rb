# frozen_string_literal: true

require "rails_helper"
require "tmpdir"
require "generators/add_auth/challenge/challenge_generator"

RSpec.describe "Challenge generator" do
  it "writes an idempotent Turnstile initializer" do
    Dir.mktmpdir("add-auth-challenge-") do |root|
      FileUtils.mkdir_p(File.join(root, "config"))
      File.write(File.join(root, "config/routes.rb"), "Rails.application.routes.draw do\nend\n")
      AddAuth::Generators::ChallengeGenerator.start(["turnstile"], destination_root: root, quiet: true)
      path = File.join(root, "config/initializers/add_auth_challenge.rb")
      expect(File.read(path)).to include("Core::Challenge::Turnstile", "TURNSTILE_SECRET_KEY", "challenge_on")
      expect(File.read(File.join(root, "config/routes.rb"))).to include("add_auth/challenge.js")
      initial = File.read(path)

      AddAuth::Generators::ChallengeGenerator.start(["turnstile"], destination_root: root, quiet: true)
      expect(File.read(path)).to eq(initial)
      expect(File.read(File.join(root, "config/routes.rb")).scan("add_auth/challenge.js").size).to eq(1)
    end
  end

  it "writes a v2 reCAPTCHA initializer when requested" do
    Dir.mktmpdir("add-auth-challenge-") do |root|
      AddAuth::Generators::ChallengeGenerator.start(["recaptcha", "--version=v2"], destination_root: root, quiet: true)
      expect(File.read(File.join(root, "config/initializers/add_auth_challenge.rb"))).to include(
        "Core::Challenge::Recaptcha", "version: :v2"
      )
    end
  end

  it "rejects unknown providers and versions" do
    Dir.mktmpdir("add-auth-challenge-") do |root|
      expect {
        AddAuth::Generators::ChallengeGenerator.new(["hcaptcha"], destination_root: root).send(:validate_provider)
      }.to raise_error(Thor::Error, /turnstile or recaptcha/)
      expect {
        AddAuth::Generators::ChallengeGenerator.new(["recaptcha"], destination_root: root, version: "v1").send(:validate_version)
      }.to raise_error(Thor::Error, /v2 or v3/)
    end
  end
end

RSpec.describe "Generated challenge production configuration" do
  %w[turnstile recaptcha].each do |provider|
    it "fails closed when #{provider} keys or hostname restrictions are absent in production" do
      Dir.mktmpdir("add-auth-challenge-") do |root|
        AddAuth::Generators::ChallengeGenerator.start([provider], destination_root: root, quiet: true)
        source_path = File.join(root, "config/initializers/add_auth_challenge.rb")
        previous = AddAuth.configuration.challenge
        allow(Rails.env).to receive(:production?).and_return(true)
        allow(ENV).to receive(:[]).and_call_original
        prefix = provider.upcase
        allow(ENV).to receive(:[]).with("#{prefix}_SITE_KEY").and_return(nil)
        allow(ENV).to receive(:[]).with("#{prefix}_SECRET_KEY").and_return(nil)
        expect { load(source_path) }.to raise_error(AddAuth::Error, /both provider keys/)
        allow(ENV).to receive(:[]).with("#{prefix}_SITE_KEY").and_return("synthetic-site")
        allow(ENV).to receive(:[]).with("#{prefix}_SECRET_KEY").and_return("synthetic-secret")
        allow(ENV).to receive(:fetch).and_call_original
        allow(ENV).to receive(:fetch).with("#{prefix}_ALLOWED_HOSTNAMES", "").and_return("")
        expect { load(source_path) }.to raise_error(AddAuth::Error, /allowed hostnames/)
        expect(AddAuth.configuration.challenge).to equal(previous)
      end
    end
  end
end
