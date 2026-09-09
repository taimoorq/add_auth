# frozen_string_literal: true

require "rspec/core"
require "rspec/expectations"
require "rspec/mocks"
require "webmock/rspec"
require_relative "browser"

WebMock.disable_net_connect!(allow_localhost: true)
raise "native-only host loaded OAuth middleware" if defined?(OmniAuth)
raise "native-only host loaded Devise" if defined?(Devise)
ActionController::Base.allow_forgery_protection = true
ActiveJob::Base.queue_adapter = :inline
RSpec.configure { |config| config.formatter = :documentation }

RSpec.describe "Native Apple package journeys" do
  let(:client) { ActionDispatch::Integration::Session.new(Rails.application) }
  let(:provider) { AddAuth.configuration.external_identities.native_provider("apple-ios") }
  let(:key) { OpenSSL::PKey::RSA.generate(2048) }

  before do
    AddAuth.configuration.rate_limit_store.clear
    Rails.cache.clear
    ActionMailer::Base.deliveries.clear
    stub_request(:get, "https://appleid.apple.com/auth/keys").to_return(status: 200,
      body: {keys: [JWT::JWK.new(key.public_key, kid: "fixture", alg: "RS256").export]}.to_json)
  end

  after { @browser&.quit }

  def challenge(intent = "sign_in")
    client.post "/mobile/apple/challenge", params: {client_id: "ios", intent: intent}, as: :json
    expect(client.response.status).to eq(201)
    client.response.parsed_body
  end

  def proof(challenge, subject)
    token = JWT.encode({iss: provider.issuer, aud: provider.audience, sub: subject, nonce: challenge.fetch("nonce"),
                       iat: Time.now.to_i, exp: Time.now.to_i + 300, email: "signed-profile@example.test", email_verified: true}, key, "RS256", kid: "fixture")
    {client_id: "ios", challenge_id: challenge.fetch("challenge_id"), nonce: challenge.fetch("nonce"), identity_token: token}
  end

  %i[turbo html no_js].each do |mode|
    it "enrolls and confirms through #{mode} before issuing a mobile session" do
      AddAuth.configuration.turbo_enabled = mode == :turbo
      email = "native-#{mode}@example.test"
      native_proof = proof(challenge("enroll"), "new-#{mode}")
      sessions_before = Session.count
      client.post "/mobile/apple/session", params: native_proof, as: :json
      expect(client.response.status).to eq(401)
      client.post "/mobile/apple/enrollment", params: native_proof.merge(email_address: email), as: :json
      expect(client.response.status).to eq(202)
      expect(client.response.parsed_body).to eq("status" => "confirmation_required")
      expect(client.response.headers["Set-Cookie"]).to be_nil
      account = User.find_by!(email_address: email)
      expect(account.password_digest).to be_nil
      expect(account.confirmed_at).to be_nil
      expect(AddAuthExternalIdentity.find_by!(user_id: account.id).subject).to eq("new-#{mode}")
      expect(Session.count).to eq(sessions_before)
      message = ActionMailer::Base.deliveries.find { |mail| mail.to == [email] }
      expect(message.subject).to eq("Confirm your email address")
      link = URI(message.body.decoded.scan(%r{https://[^[:space:]<>]+}).first)
      @browser = Capybara::Session.new((mode == :no_js) ? :add_auth_no_js : :add_auth_chrome, Rails.application)
      @browser.visit link.request_uri
      expect(@browser).to have_button("Confirm this email address")
      expect(@browser.evaluate_script("typeof window.Turbo")).to eq("undefined") if mode == :html
      expect(account.reload.confirmed_at).to be_nil
      @browser.click_button "Confirm this email address"
      expect(@browser).to have_css("h1", text: "Sign in")
      expect(account.reload.confirmed_at).to be_present
      expect(Session.count).to eq(sessions_before)
      client.post "/mobile/apple/enrollment", params: native_proof.merge(email_address: "replay-#{email}"), as: :json
      expect(client.response.status).to eq(401)
      expect(User.find_by(email_address: "replay-#{email}")).to be_nil
      client.post "/mobile/apple/session", params: proof(challenge, "new-#{mode}"), as: :json
      expect(client.response.status).to eq(201)
      expect(client.response.parsed_body.fetch("user_id")).to eq(account.id)
      bearer = client.response.parsed_body.fetch("token")
      expect(bearer).to match(AddAuth::Core::MobileProfile::PATTERN)
      expect(client.response.headers["Set-Cookie"]).to be_nil
      client.get "/mobile/session", headers: {"Authorization" => "Bearer #{bearer}"}
      expect(client.response.status).to eq(200)
      client.delete "/mobile/session", headers: {"Authorization" => "Bearer #{bearer}"}
      expect(client.response.status).to eq(204)
      client.get "/mobile/session", headers: {"Authorization" => "Bearer #{bearer}"}
      expect(client.response.status).to eq(401)
    end
  end

  it "never attaches a new identity to an existing address or creates accounts during sign-in" do
    account = User.create!(email_address: "existing-native@example.test", password: "correct-password", confirmed_at: Time.current)
    counts = [User.count, AddAuthExternalIdentity.count, Session.count, AddAuthAccountToken.count]
    sign_in = proof(challenge, "unbound-subject")
    client.post "/mobile/apple/session", params: sign_in.merge(email_address: account.email_address), as: :json
    expect(client.response.status).to eq(401)
    client.post "/mobile/apple/enrollment", params: sign_in.merge(email_address: "other@example.test"), as: :json
    expect(client.response.status).to eq(401)
    enrollment = proof(challenge("enroll"), "unbound-subject")
    client.post "/mobile/apple/enrollment", params: enrollment.merge(email_address: account.email_address), as: :json
    expect([401, 202]).to include(client.response.status)
    expect([User.count, AddAuthExternalIdentity.count, Session.count, AddAuthAccountToken.count]).to eq(counts)
    expect(account.reload.authenticate("correct-password")).to eq(account)
  end

  it "rolls back a newly submitted account when the provider identity is already owned" do
    account = User.create!(email_address: "bound-native@example.test", confirmed_at: Time.current)
    identity = AddAuthExternalIdentity.create!(user: account, namespace: provider.namespace("owned-subject"), provider_id: provider.id,
      issuer: provider.issuer, audience: provider.audience, subject: "owned-subject", provenance: "reviewed-import",
      credential_version: "original", linked_at: Time.current - 1)
    counts = [User.count, AddAuthAddressClaim.count, AddAuthAccountToken.count, Session.count]
    enrollment = proof(challenge("enroll"), "owned-subject")
    client.post "/mobile/apple/enrollment", params: enrollment.merge(email_address: "cannot-move@example.test"), as: :json
    expect(client.response.status).to eq(401)
    expect([User.count, AddAuthAddressClaim.count, AddAuthAccountToken.count, Session.count]).to eq(counts)
    expect(identity.reload.user_id).to eq(account.id)
  end
end

exit RSpec::Core::Runner.new(RSpec::Core::ConfigurationOptions.new([])).run_specs(RSpec.world.ordered_example_groups)
