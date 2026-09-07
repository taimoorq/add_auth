# frozen_string_literal: true

require "rails_helper"
require_relative "../support/reauthentication"

RSpec.describe "Public reauthentication", type: :request, database: true do
  include_context "public reauthentication"
  include ActiveJob::TestHelper

  let!(:user) { User.create!(email_address: "reauth@example.test", password: "correct-password") }

  def sign_in
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    expect(response).to have_http_status(303)
  end

  it "returns to a configured GET and requires a separate, currently authorized mutation" do
    sign_in
    old_cookie = cookies[:session_id]
    original = user.reload.updated_at
    patch "/sensitive", params: {user_id: "forged", untrusted_body: "never replay this"}
    expect(response).to redirect_to("/reauthenticate?purpose=manage_profile")
    post "/reauthenticate/password", params: {purpose: :manage_profile, password: "correct-password", return_to: "https://evil.example"}
    expect(response).to redirect_to("/sensitive")
    expect(response).to have_http_status(303)
    expect(user.reload.updated_at).to eq(original)
    expect(Session.count).to eq(1)
    get "/sensitive"
    expect(response.body).to include("Review profile change")
    patch "/sensitive"
    expect(response).to redirect_to("/sensitive/done")
    cookies[:session_id] = old_cookie
    get "/sensitive"
    expect(response).to redirect_to("/sign-in")
  end

  it "denies unknown and passkey-only purposes without accepting fresh weaker proof" do
    sign_in
    get "/reauthenticate", params: {purpose: ["manage_profile"]}
    expect(response).to have_http_status(404)
    get "/reauthenticate", params: {purpose: :strong}
    expect(response.body).to include("No permitted verification method")
    post "/reauthenticate/password", params: {purpose: :strong, password: "correct-password"},
      headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response).to have_http_status(422)
    expect(response.body).to include('target="latchkey-content"')
    expect(Session.last.elevated_at).to be_nil
  end

  it "requires CSRF and a new proof after expiry, even when a confirmation page is open" do
    sign_in
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    post "/reauthenticate/password", params: {purpose: :manage_profile, password: "correct-password"}
    expect(response).to have_http_status(422)
    get "/reauthenticate", params: {purpose: :manage_profile}
    expect(response.headers["Cache-Control"]).to eq("no-store")
    csrf = Nokogiri::HTML(response.body).at_css('meta[name="csrf-token"]')["content"]
    post "/reauthenticate/password", params: {purpose: :manage_profile, password: "correct-password", authenticity_token: csrf}
    expect(response).to have_http_status(303)
    get "/sensitive"
    csrf = Nokogiri::HTML(response.body).at_css('input[name="authenticity_token"]')["value"]
    Session.last.update!(elevation_expires_at: Time.current)
    patch "/sensitive", params: {authenticity_token: csrf}
    expect(response).to redirect_to("/reauthenticate?purpose=manage_profile")
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  it "delivers a distinct browser-bound proof and rejects cross-purpose and cross-browser submission" do
    sign_in
    perform_enqueued_jobs do
      post "/reauthenticate/email", params: {purpose: :manage_profile, email_address: "other@example.test"}
    end
    expect(response).to have_http_status(303)
    message = ActionMailer::Base.deliveries.last
    expect(message.to).to eq([user.email_address])
    expect(message.subject).to eq("Verify your current session")
    url = URI.parse(message.body.decoded[/http[^\s]+/])
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    outsider = ActionDispatch::Integration::Session.new(Rails.application)
    outsider.get url.request_uri
    expect(outsider.response.body).to include("Return to the browser where you started")
    outsider.post "/reauthenticate/link", params: {token: token}
    expect(outsider.response.status).to eq(422)
    post "/sign-in/link", params: {token: token, switch_account: "1"}
    expect(response).to have_http_status(422)
    get url.request_uri
    expect(response.body).to include("Confirm this verification")
    expect(LatchkeySignInToken.last.consumed_at).to be_nil
    post "/reauthenticate/link", params: {token: token, purpose: :strong}
    expect(response).to redirect_to("/sensitive")
    expect(Session.count).to eq(1)
    expect(Session.last.elevation_purpose).to eq("manage_profile")
    post "/reauthenticate/link", params: {token: token}
    expect(response).to have_http_status(422)
  end

  it "returns safely after password rotation if the purpose is removed before the response" do
    sign_in
    old_cookie = cookies[:session_id]
    allow(Latchkey::Rails::Runtime).to receive(:elevate_password).and_wrap_original do |original, **args|
      result = original.call(**args)
      expect(result).to be_success
      Latchkey.configuration.step_up.purposes.delete(:manage_profile)
      result
    end
    post "/reauthenticate/password", params: {purpose: :manage_profile, password: "correct-password"}
    expect(response).to have_http_status(303)
    expect(response).to redirect_to("/")
    expect(cookies[:session_id]).not_to eq(old_cookie)
    patch "/sensitive"
    expect(response).not_to redirect_to("/sensitive/done")
  end

  it "returns safely after email consumption if its purpose disappears before the response" do
    sign_in
    perform_enqueued_jobs { post "/reauthenticate/email", params: {purpose: :manage_profile} }
    url = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    allow(Latchkey::Rails::Runtime).to receive(:email).and_wrap_original do |original, **args|
      service = original.call(**args)
      allow(service).to receive(:reauthenticate).and_wrap_original do |consume, **proof|
        result = consume.call(**proof)
        expect(result).to be_success
        Latchkey.configuration.step_up.purposes.delete(:manage_profile)
        result
      end
      service
    end
    post "/reauthenticate/link", params: {token: token}
    expect(response).to have_http_status(303)
    expect(response).to redirect_to("/")
    expect(LatchkeySignInToken.last.consumed_at).to be_present
    expect(Session.count).to eq(1)
  end
end
