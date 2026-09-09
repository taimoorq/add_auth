# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Optional mobile session JSON transport", type: :request, database: true do
  let!(:user) { User.create!(email_address: "native@example.test", password: "correct-password") }
  let(:config) { AddAuth.configuration }

  around do |example|
    previous = config.mobile.to_h
    eligible, challenge, challenge_on = config.eligible, config.challenge, config.challenge_on
    config.mobile.enabled = true
    config.mobile.lifetime = 30 * 86_400
    config.mobile.idle_timeout = 14 * 86_400
    config.mobile.clients = %w[android ios]
    example.run
  ensure
    previous.each { |key, value| config.mobile.public_send("#{key}=", value) }
    config.eligible, config.challenge, config.challenge_on = eligible, challenge, challenge_on
  end

  def login(client_id: "android", password: "correct-password", email_address: user.email_address)
    post "/mobile/session", params: {email_address: email_address, password: password, client_id: client_id}, as: :json
    response.parsed_body
  end

  def authorization(token) = {"Authorization" => "Bearer #{token}"}

  it "returns one opaque credential in JSON, no cookie, and resumes through Authorization" do
    body = login
    expect(response).to have_http_status(:created)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(response.headers["Set-Cookie"]).to be_nil
    expect(body.keys).to contain_exactly("token", "token_type", "expires_at", "session_id", "user_id")
    expect(body.fetch("token")).to match(AddAuth::Core::MobileProfile::PATTERN)
    get "/mobile/session", headers: authorization(body.fetch("token"))
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body["user_id"]).to eq(user.id)
    expect(response.body).not_to include(body.fetch("token"))
  end

  it "never accepts a browser session, parameter token or malformed bearer as API authority" do
    post "/session", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to have_http_status(:see_other)
    get "/mobile/session"
    expect(response).to have_http_status(:unauthorized)
    token = login.fetch("token")
    get "/mobile/session", params: {token: token}
    expect(response).to have_http_status(:unauthorized)
    [token, "Bearer  #{token}", "Bearer #{token},#{token}", "Bearer lk1:#{"a" * 43}"].each do |header|
      get "/mobile/session", headers: {"Authorization" => header}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  it "refuses disabled routes and unregistered clients without creating authority" do
    login(client_id: "unknown")
    expect(response).to have_http_status(:unauthorized)
    expect(Session.count).to eq(0)
    config.mobile.enabled = false
    login
    expect(response).to have_http_status(:not_found)
  end

  it "applies the same current denial and strict policy at password login and resume" do
    token = login.fetch("token")
    config.eligible = ->(_) { false }
    login
    expect(response).to have_http_status(:forbidden)
    expect(response.parsed_body.fetch("error")).to eq("disabled")
    login(password: "wrong-password")
    expect(response).to have_http_status(:unauthorized)
    expect(response.parsed_body.fetch("error")).to eq("invalid_credentials")
    get "/mobile/session", headers: authorization(token)
    expect(response).to have_http_status(:unauthorized)
    config.eligible = ->(_) { true }
    user.update_column(:add_auth_strict, true)
    login
    expect(response).to have_http_status(:unauthorized)
    get "/mobile/session", headers: authorization(token)
    expect(response).to have_http_status(:unauthorized)
  end

  it "retains shared captcha policy and distinguishes rejection, outage and rate limits" do
    config.challenge_on = [:sign_in]
    config.challenge = AddAuth::Core::Challenge::Test.new(mode: :rejected)
    login
    expect(response).to have_http_status(:unprocessable_entity)
    config.challenge = AddAuth::Core::Challenge::Test.new(mode: :unavailable)
    login
    expect(response).to have_http_status(:service_unavailable)
    expect(response.headers["Retry-After"]).to eq("300")
    config.challenge_on = []
    4.times { login(password: "wrong-password") }
    expect(response).to have_http_status(:too_many_requests)
    expect(Session.count).to eq(0)
  end

  it "revokes only the current device on logout, with safe listing and owned-device revocation" do
    one = login
    two = login(client_id: "ios")
    get "/mobile/sessions", headers: authorization(one.fetch("token"))
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("sessions").map { |row| row.fetch("client_id") }).to contain_exactly("android", "ios")
    expect(response.body).not_to include("token_digest", one.fetch("token"), two.fetch("token"))
    delete "/mobile/session", headers: authorization(one.fetch("token"))
    expect(response).to have_http_status(:no_content)
    get "/mobile/session", headers: authorization(one.fetch("token"))
    expect(response).to have_http_status(:unauthorized)
    get "/mobile/session", headers: authorization(two.fetch("token"))
    expect(response).to have_http_status(:ok)
    other = User.create!(email_address: "unrelated@example.test", password: "correct-password")
    other_grant = AddAuth::Rails::Runtime.sessions.start(user: other, method: :password)
    delete "/mobile/sessions/#{other_grant.session.id}", headers: authorization(two.fetch("token"))
    expect(response).to have_http_status(:not_found)
    expect(other_grant.session.reload.revoked_at).to be_nil
  end

  it "requires current fresh proof before sign-out-everywhere and retires browser authority too" do
    token = login.fetch("token")
    browser = AddAuth::Rails::Runtime.sessions.start(user: user, method: :password)
    post "/mobile/sessions/revoke-all", params: {password: "wrong-password"}, headers: authorization(token), as: :json
    expect(response).to have_http_status(:unauthorized)
    expect(browser.session.reload.revoked_at).to be_nil
    post "/mobile/sessions/revoke-all", params: {password: "correct-password"}, headers: authorization(token), as: :json
    expect(response).to have_http_status(:no_content)
    expect(browser.session.reload.revoked_at).to be_present
    get "/mobile/session", headers: authorization(token)
    expect(response).to have_http_status(:unauthorized)
  end

  it "does not grant access when the authority store is unavailable" do
    token = login.fetch("token")
    allow(AddAuth::Rails::Runtime).to receive(:sessions).and_raise(AddAuth::Error, "private backend details")
    get "/mobile/session", headers: authorization(token)
    expect(response).to have_http_status(:service_unavailable)
    expect(response.body).not_to include("private backend", token)
  end
end
