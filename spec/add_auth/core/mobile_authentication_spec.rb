# frozen_string_literal: true

require "spec_helper"
require "add_auth/core/mobile_authentication"

RSpec.describe "Password API policy disclosure" do
  let(:user) { Struct.new(:id, :password_digest).new(1, "current-version") }
  let(:store) { double }
  let(:denial) { double(call: :unconfirmed) }
  let(:sessions) do
    AddAuth::Core::Sessions.new(store: store, digest: double, eligible: ->(_) { false }, verified_denial: denial)
  end

  before do
    allow(store).to receive(:with_identifier) { |**_, &block| block.call(user) }
  end

  it "discloses Core account state only after the current password proof and explicit opt-in" do
    %i[unconfirmed locked disabled].each do |reason|
      allow(denial).to receive(:call).and_return(reason)
      result = sessions.authenticate_result(identifier: "user@example.test", password: "secret", disclose_policy: true) { user }
      expect(result.reason).to eq(reason)
      expect(result.user).to be_nil
      expect(result.grant).to be_nil
    end
  end

  it "keeps wrong, stale and absent password evidence generic and never calls the disclosure policy" do
    [nil, Struct.new(:id, :password_digest).new(1, "retired-version"), Struct.new(:id, :password_digest).new(2, "current-version")].each do |proof|
      result = sessions.authenticate_result(identifier: "user@example.test", password: "wrong", disclose_policy: true) { proof }
      expect(result.reason).to eq(:invalid_credentials)
    end
    expect(denial).not_to have_received(:call)
  end

  it "keeps the existing browser hook generic and rejects undeclared public denial reasons" do
    expect(sessions.authenticate(identifier: "user@example.test", password: "secret") { user }).to be_nil
    expect(denial).not_to have_received(:call)
    allow(denial).to receive(:call).and_return(:private_host_state)
    expect(sessions.authenticate_result(identifier: "user@example.test", password: "secret", disclose_policy: true) { user }.reason).to eq(:invalid_credentials)
  end
end

RSpec.describe AddAuth::Core::MobileAuthentication do
  let(:intake) { double(call: "normalized@example.test") }
  let(:sessions) { double(authenticate_result: AddAuth::Result.failure(reason: :invalid_credentials)) }
  let(:verify) { double(call: nil) }
  let(:profile) { AddAuth::Core::MobileProfile.new(lifetime: 86_400, idle_timeout: 1800, clients: ["android"]) }
  subject(:service) { described_class.new(sessions: sessions, profile: profile, intake: intake, verify_password: verify) }

  def authenticate(**args)
    service.password(identifier: "submitted@example.test", password: "correct-password", client_id: "android", ip: "127.0.0.1", **args)
  end

  it "keeps limiter and challenge outcomes ahead of password work" do
    %i[rate_limited challenge_rejected challenge_unavailable invalid_credentials].each do |reason|
      allow(intake).to receive(:call).and_return(reason)
      expect(authenticate.reason).to eq(reason)
    end
    expect(sessions).not_to have_received(:authenticate_result)
    expect(verify).not_to have_received(:call)
  end

  it "rejects malformed credentials and unregistered clients before expensive verification" do
    [nil, {}, "", "x" * 1025, "a\0b", "\xff".b.force_encoding("UTF-8")].each do |password|
      expect(authenticate(password: password).reason).to eq(:invalid_credentials)
    end
    expect(authenticate(client_id: "unregistered").reason).to eq(:invalid_credentials)
    expect(sessions).not_to have_received(:authenticate_result)
  end

  it "uses the locked Sessions result and normalizer, excluding unbounded device hints" do
    result = AddAuth::Result.success(user: Struct.new(:id).new(1), strategy: :password, grant: double)
    allow(sessions).to receive(:authenticate_result) do |**arguments, &block|
      expect(arguments).to include(identifier: "normalized@example.test", transport: :mobile, disclose_policy: true, user_agent: nil)
      block.call
      result
    end
    expect(authenticate(user_agent: "x" * 513)).to equal(result)
    expect(verify).to have_received(:call).with(identifier: "normalized@example.test", password: "correct-password")
  end
end
