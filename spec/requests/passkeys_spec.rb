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
    LatchkeyCredential.last
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
    expect(LatchkeyCeremony.count).to eq(0)
    get "/passkeys"
    expect(response.headers).to include("Cache-Control" => "no-store", "Referrer-Policy" => "no-referrer")
    csrf = Nokogiri::HTML(response.body).at_css('meta[name="csrf-token"]')["content"]
    expect(enroll(headers: {"X-CSRF-Token" => csrf})).to be_present
    post "/passkeys", params: {transaction: "untrusted", credential: {}}, as: :json
    expect(response).to have_http_status(422)
    expect(LatchkeyCredential.count).to eq(1)
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
    expect(response.body).to include('target="latchkey-content"')
    delete "/passkeys/#{credential.id}"
    expect(response).to have_http_status(422)
    expect(credential.reload).to have_attributes(nickname: "Passkey", revoked_at: nil)
  end
end
