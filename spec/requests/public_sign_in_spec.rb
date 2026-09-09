# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Public sign in", type: :request, database: true do
  include ActiveJob::TestHelper

  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }

  def request_mail
    perform_enqueued_jobs do
      post "/sign-in/email", params: {email_address: user.email_address}
    end
    expect(response).to have_http_status(:see_other)
    message = ActionMailer::Base.deliveries.last
    expect(message).to be_present
    URI.parse(message.body.decoded[/http[^\s]+/])
  end

  it "renders usable password/email forms and signs in without JavaScript" do
    get "/sign-in"
    expect(response).to have_http_status(:ok)
    expect(response.body).to include('autocomplete="current-password"', "turbo-cache-control", "/add_auth.css")
    post "/sign-in/password", params: {email_address: " PERSON@EXAMPLE.TEST ", password: "wrong"}
    expect(response).to have_http_status(:unprocessable_entity)
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to redirect_to("/")
    expect(response).to have_http_status(:see_other)
    expect(Session.last.authenticated_with).to eq("password")
    expect(Session.last.token_digest).to be_present
    get "/"
    expect(response.body).to eq("Signed in")
  end

  it "queues the same public outcome for known, unknown, disabled and throttled accounts" do
    statuses = []
    [user.email_address, "missing@example.test"].each do |email|
      post "/sign-in/email", params: {email_address: email}
      statuses << [response.status, response.location, response.body]
    end
    expect(enqueued_jobs.size).to eq(2)
    expect(enqueued_jobs.inspect).not_to include(user.email_address, "missing@example.test")
    expect(AddAuthSignInToken.count).to eq(0)
    original = AddAuth.configuration.eligible
    AddAuth.configuration.eligible = ->(_) { false }
    6.times do
      post "/sign-in/email", params: {email_address: user.email_address}
      statuses << [response.status, response.location, response.body]
    end
    expect(statuses.uniq.size).to eq(1)
  ensure
    AddAuth.configuration.eligible = original
  end

  it "delivers an inert link, requires confirmation and rejects replay" do
    url = request_mail
    record = AddAuthSignInToken.last
    expect(record.delivered_at).to be_present
    expect(record.delivery_payload).to be_nil
    2.times do
      get url.request_uri
      expect(response).to have_http_status(:ok)
      expect(response.body).to include("p•••@example.test", "Sign in to this account")
      expect(response.headers["Cache-Control"]).to eq("no-store")
      expect(response.headers["Referrer-Policy"]).to eq("no-referrer")
      expect(Session.count).to eq(0)
      expect(record.reload.consumed_at).to be_nil
    end
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    post "/sign-in/link", params: {token: token, switch_account: "1"}
    expect(response).to have_http_status(:see_other)
    expect(Session.last.authenticated_with).to eq("email_link")
    get "/"
    expect(response.body).to eq("Signed in")
    post "/sign-in/link", params: {token: token, switch_account: "1"}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(Session.count).to eq(1)
  end

  it "denies another browser's POST without burning the bound delivered link" do
    previous = AddAuth.configuration.email_link.same_browser
    AddAuth.configuration.email_link.same_browser = true
    url = request_mail
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    outsider = ActionDispatch::Integration::Session.new(Rails.application)
    outsider.post "/sign-in/link", params: {token: token, switch_account: "1"},
      headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(outsider.response.status).to eq(422)
    expect(outsider.response.body).to include('target="add_auth-content"', "Request a new link")
    expect(AddAuthSignInToken.last.consumed_at).to be_nil
    expect(Session.count).to eq(0)
    post "/sign-in/link", params: {token: token, switch_account: "1"}
    expect(response).to have_http_status(303)
    expect(Session.count).to eq(1)
  ensure
    AddAuth.configuration.email_link.same_browser = previous
  end

  it "requires real CSRF protection for both password and link POSTs" do
    url = request_mail
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    post "/sign-in/link", params: {token: token}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(AddAuthSignInToken.last.consumed_at).to be_nil
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(Session.count).to eq(0)
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  it "uses shared stream partials and forces frame entry to a full page" do
    get "/sign-in", headers: {"Turbo-Frame" => "private-panel"}
    expect(response.body).to include('name="turbo-visit-control" content="reload"')
    post "/sign-in/password", params: {email_address: user.email_address, password: "wrong"},
      headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(response.body).to include('target="add_auth-content"', 'action="update"', "Email or password is incorrect")
  end

  it "returns a full destination document for Turbo redirects while retaining explicit stream GETs" do
    get "/sign-in", headers: {"Accept" => "text/vnd.turbo-stream.html, text/html, application/xhtml+xml"}
    expect(response.media_type).to eq("text/html")
    expect(response.body).to include("<!DOCTYPE html>", "add_auth-content")
    get "/sign-in", headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response.media_type).to eq("text/vnd.turbo-stream.html")
    expect(response.body).to include('<turbo-stream action="update" target="add_auth-content">')
  end

  it "supports framework classes and disabling the default stylesheet" do
    config = AddAuth.configuration
    old_css, old_classes = config.stylesheet, config.css_classes
    config.stylesheet = nil
    config.css_classes = {input: "form-control", button: "btn btn-primary"}
    get "/sign-in"
    expect(response.body).to include('class="form-control"', 'class="btn btn-primary"')
    expect(response.body).not_to include('rel="stylesheet"')
  ensure
    config.stylesheet, config.css_classes = old_css, old_classes
  end

  it "renders one provider widget per protected form and accepts its canonical token" do
    config = AddAuth.configuration
    old_challenge, old_on = config.challenge, config.challenge_on
    config.challenge = AddAuth::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "secret",
      transport: ->(**) {
        [200, JSON.generate("success" => true, "action" => "sign_in", "hostname" => "example.test")]
      })
    config.challenge_on = [:sign_in]

    get "/sign-in"
    expect(response.body.scan("challenges.cloudflare.com/turnstile/v0/api.js").size).to eq(1)
    expect(Nokogiri::HTML(response.body).css('[data-controller="add-auth-challenge"]').size).to eq(1)
    expect(response.body).to include('data-add-auth-challenge-target="token"')

    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password", challenge_token: "token"}
    expect(response).to have_http_status(:see_other)
  ensure
    config.challenge, config.challenge_on = old_challenge, old_on if config
  end

  it "keeps v2 reCAPTCHA independent from the v3 score contract" do
    config = AddAuth.configuration
    old_challenge, old_on = config.challenge, config.challenge_on
    config.challenge = AddAuth::Core::Challenge::Recaptcha.new(site_key: "site", secret_key: "secret", version: :v2,
      transport: ->(**) { [200, JSON.generate("success" => true, "hostname" => "example.test")] })
    config.challenge_on = [:email_link]

    get "/sign-in"
    expect(response.body).to include('data-add-auth-challenge-provider-value="recaptcha-v2"', "render=explicit")
    expect(response.body).to include('name="challenge_token"')
  ensure
    config.challenge, config.challenge_on = old_challenge, old_on if config
  end

  it "serves the v3 bridge with cacheable provider-independent JavaScript" do
    get "/add_auth/challenge.js"
    expect(response).to have_http_status(:ok)
    expect(response.media_type).to eq("text/javascript")
    expect(response.body).to include("beforeCache()", "requestSubmit")
    expect(response.headers["Cache-Control"]).to include("max-age")
  end

  it "upgrades only Rails-verified legacy cookies and cannot reuse the old ID afterward" do
    row = user.sessions.create!
    old_deadline = AddAuth.configuration.session.legacy_bridge_until
    AddAuth.configuration.session.legacy_bridge_until = 10.minutes.from_now
    request = ActionDispatch::TestRequest.create(Rails.application.env_config)
    jar = ActionDispatch::Cookies::CookieJar.build(request, {})
    jar.signed[:session_id] = row.id
    signed_id = jar[:session_id]
    cookies[:session_id] = signed_id + "tampered"
    get "/"
    expect(response).to redirect_to("/sign-in")
    expect(row.reload.token_digest).to be_nil
    cookies[:session_id] = signed_id
    get "/"
    expect(response.body).to eq("Signed in")
    expect(row.reload.token_digest).to be_present
    expect(response.headers["Set-Cookie"].to_s).to include("httponly", "samesite=lax")
    cookies[:session_id] = signed_id
    get "/"
    expect(response).to redirect_to("/sign-in")
  ensure
    AddAuth.configuration.session.legacy_bridge_until = old_deadline
  end

  it "requires deliberate account switching and revokes the replaced browser session" do
    other = User.create!(email_address: "other@example.test", password: "other-password")
    url = request_mail
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    post "/sign-in/password", params: {email_address: other.email_address, password: "other-password"}
    previous = Session.last
    post "/sign-in/link", params: {token: token}
    expect(response).to have_http_status(422)
    expect(AddAuthSignInToken.last.consumed_at).to be_nil
    get url.request_uri
    expect(response.body).to include("replace any account")
    post "/sign-in/link", params: {token: token, switch_account: "1"}
    expect(response).to have_http_status(303)
    expect(previous.reload.revoked_at).to be_present
    expect(Session.last.user_id).to eq(user.id)
  end

  it "revokes outstanding email proof on password reset and deletes it with an account" do
    url = request_mail
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    user.update!(password: "new-password")
    post "/sign-in/link", params: {token: token}
    expect(response).to have_http_status(422)
    expect(Session.count).to eq(0)
    user.destroy!
    expect(AddAuthSignInToken.count).to eq(0)
  end

  it "fails closed with useful HTML during queue and challenge outages" do
    allow(AddAuth::EmailRequestJob).to receive(:perform_later).and_return(false)
    post "/sign-in/email", params: {email_address: user.email_address}
    expect(response).to have_http_status(503)
    expect(response.headers["Retry-After"]).to eq("60")
    config = AddAuth.configuration
    old_challenge, old_on = config.challenge, config.challenge_on
    config.challenge = AddAuth::Core::Challenge::Test.new(mode: :unavailable)
    config.challenge_on = [:sign_in]
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to have_http_status(503)
    expect(Session.count).to eq(0)
  ensure
    config.challenge, config.challenge_on = old_challenge, old_on if config
  end

  it "only bypasses a challenge outage when the host explicitly chooses open" do
    config = AddAuth.configuration
    old_challenge, old_on, old_policy = config.challenge, config.challenge_on, config.challenge_when_unavailable
    config.challenge = AddAuth::Core::Challenge::Test.new(mode: :unavailable)
    config.challenge_on = [:sign_in]
    config.challenge_when_unavailable = :open

    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to have_http_status(:see_other)
    expect(Session.last.authenticated_with).to eq("password")
  ensure
    config.challenge, config.challenge_on, config.challenge_when_unavailable = old_challenge, old_on, old_policy if config
  end

  it "requires session-bound CSRF for null origin and denies a foreign origin even with a token" do
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    get "/sign-in"
    csrf = Nokogiri::HTML(response.body).at_css('meta[name="csrf-token"]')["content"]
    values = {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
    post "/sign-in/password", params: values, headers: {"Origin" => "https://foreign.example"}
    expect(response).to have_http_status(422)
    post "/sign-in/password", params: values.except(:authenticity_token), headers: {"Origin" => "null"}
    expect(response).to have_http_status(422)
    post "/sign-in/password", params: values, headers: {"Origin" => "null"}
    expect(response).to have_http_status(303)
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end
end
