# frozen_string_literal: true

require "rails_helper"
require "webauthn/fake_client"
require_relative "../support/passkey_runtime"

RSpec.describe "Public passkey verification", type: :request, database: true do
  include_context "passkey runtime"
  let!(:user) { User.create!(email_address: "request-passkey@example.test", password: "correct-password") }
  let(:authenticator) { WebAuthn::FakeClient.new("http://localhost", encoding: :base64url) }

  before do
    host! "localhost"
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    post "/reauthenticate/password", params: {purpose: :manage_passkeys, password: "correct-password"}
  end

  def enroll(headers: {})
    post "/passkeys/options", headers: headers, as: :json
    expect(response).to have_http_status(200)
    start = response.parsed_body
    credential = authenticator.create(challenge: start.fetch("publicKey").fetch("challenge"), user_verified: true)
    post "/passkeys", params: {transaction: start.fetch("transaction"), credential: credential}, headers: headers, as: :json
    expect(response).to have_http_status(200)
    AddAuthCredential.last
  end

  def elevate(purpose)
    post "/reauthenticate/passkey/options", params: {purpose: purpose}, as: :json
    expect(response).to have_http_status(200)
    start = response.parsed_body
    credential = authenticator.get(challenge: start.fetch("publicKey").fetch("challenge"), user_verified: true,
      backup_state: false, user_handle: Base64.urlsafe_decode64(user.reload.webauthn_id))
    post "/reauthenticate/passkey", params: {transaction: start.fetch("transaction"), credential: credential}, as: :json
    expect(response).to have_http_status(200)
  end

  it "requires real CSRF for options and credential persistence and protects the confirmation page" do
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    post "/passkeys/options", as: :json
    expect(response).to have_http_status(422)
    expect(AddAuthCeremony.count).to eq(0)
    get "/passkeys"
    expect(response.headers).to include("Cache-Control" => "no-store", "Referrer-Policy" => "no-referrer")
    csrf = Nokogiri::HTML(response.body).at_css('meta[name="csrf-token"]')["content"]
    expect(enroll(headers: {"X-CSRF-Token" => csrf})).to be_present
    post "/passkeys", params: {transaction: "untrusted", credential: {}}, as: :json
    expect(response).to have_http_status(422)
    expect(AddAuthCredential.count).to eq(1)
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  it "lets strict accounts sign out everywhere using verified UV and rejects the password shortcut" do
    enroll
    elevate(:manage_policy)
    post "/passkeys/policy", params: {policy: "strict", acknowledged: "1"}
    expect(response).to have_http_status(303)
    post "/sessions/revoke-all", params: {password: "correct-password"}
    expect(response).to have_http_status(422)
    expect(Session.where(revoked_at: nil).count).to eq(1)
    elevate(:sign_out_everywhere)
    get "/sessions/revoke-all"
    expect(response.body).not_to include('name="password"')
    post "/sessions/revoke-all"
    expect(response).to redirect_to("/sign-in")
    expect(Session.where(revoked_at: nil)).to be_empty
  end

  it "scopes credential changes to the current account and returns shared Turbo failures" do
    credential = enroll
    other = User.create!(email_address: "other@example.test", password: "correct-password")
    credential.update!(user: other)
    patch "/passkeys/#{credential.id}", params: {nickname: "stolen"}, headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response).to have_http_status(422)
    expect(response.body).to include('target="add_auth-content"')
    delete "/passkeys/#{credential.id}"
    expect(response).to have_http_status(422)
    expect(credential.reload).to have_attributes(nickname: "Passkey", revoked_at: nil)
  end

  it "returns safely after passkey rotation when the purpose disappears" do
    enroll
    allow(AddAuth::Rails::Runtime).to receive(:passkeys).and_wrap_original do |original|
      service = original.call
      allow(service).to receive(:authenticate).and_wrap_original do |verify, **args|
        result = verify.call(**args)
        expect(result).to be_success
        AddAuth.configuration.step_up.purposes.delete(:strong)
        result
      end
      service
    end
    elevate(:strong)
    expect(response.parsed_body).to eq("redirect" => "/")
    expect(Session.last.elevation_purpose).to eq("strong")
  end
end

RSpec.describe "Anonymous passkey availability", type: :request, database: true do
  include_context "passkey runtime"

  before { host! "localhost" }

  it "returns an honest 503 for invalid configuration without creating a ceremony or session" do
    config = AddAuth.configuration.passkeys
    original = config.dup
    [{rp_id: nil}, {origins: []}, {origins: [nil]}, {anonymous_limit: 0}].each do |invalid|
      config.members.each { |field| config[field] = original[field] }
      invalid.each { |field, value| config[field] = value }
      post "/passkeys/sign-in/options", as: :json
      expect(response).to have_http_status(503)
      expect(response.headers).to include("Cache-Control" => "no-store", "Retry-After" => "60")
      expect(response.parsed_body.fetch("error")).to include("temporarily unavailable")
    end
    expect(AddAuthCeremony.count).to eq(0)
    expect(Session.count).to eq(0)
  end

  it "caps creation across different IP addresses and allows existing ceremonies to be cancelled" do
    AddAuth.configuration.passkeys.anonymous_limit = 2
    starts = 3.times.map do |attempt|
      post "/passkeys/sign-in/options", headers: {"REMOTE_ADDR" => "192.0.2.#{attempt + 1}"}, as: :json
      [response.status, response.parsed_body]
    end
    expect(starts.map(&:first)).to eq([200, 200, 429])
    expect(AddAuthCeremony.count).to eq(2)
    expect(Session.count).to eq(0)
    post "/passkeys/cancel", params: {transaction: starts.first.last.fetch("transaction")}, as: :json
    expect(response).to have_http_status(204)
    expect(AddAuthCeremony.where.not(consumed_at: nil).count).to eq(1)
  end
end
