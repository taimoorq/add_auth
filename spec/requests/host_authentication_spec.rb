# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Rails generator host", type: :request, database: true do
  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }

  it "boots the engine, signs in through host password auth, resumes and signs out" do
    get "/"
    expect(response).to redirect_to("/sign-in")
    get "/session/new"
    expect(response).to have_http_status(:ok)
    expect(response.body).to include("password")
    post "/session", params: {email_address: user.email_address, password: "correct-password"}
    expect(Session.count).to eq(1)
    expect(cookies[:session_id]).to be_present
    get "/"
    expect(response.body).to eq("Signed in")
    delete "/session"
    expect(Session.last.revoked_at).to be_present
    get "/"
    expect(response).to redirect_to("/sign-in")
  end

  it "does not create sessions for unknown or wrong credentials" do
    [user.email_address, "unknown@example.test"].each do |email|
      post "/session", params: {email_address: email, password: "incorrect"}
      expect(response).to have_http_status(:unprocessable_entity)
      expect(Session.count).to eq(0)
    end
  end

  it "preserves host reset token invalidation and session revocation" do
    user.sessions.create!
    token = user.password_reset_token
    put "/passwords/#{token}", params: {password: "replacement-password", password_confirmation: "replacement-password"}
    expect(response).to redirect_to("/session/new")
    expect(Session.count).to eq(0)
    expect(User.find_by_password_reset_token(token)).to be_nil
  end

  it "derives purpose-separated default digests from the real Rails key generator" do
    config = AddAuth.configuration
    expect(config.session_token_digest.digest("token")).not_to eq(config.sign_in_token_digest.digest("token"))
    expect(AddAuth::Rails::Engine).not_to be_isolated
  end
  it "requests a host reset email, follows the link, and invalidates every old session and email proof" do
    initial = AddAuth::Rails::Runtime.sessions.start(user: user, method: :password)
    AddAuth::Rails::Runtime.email.issue(identifier: user.email_address)
    old_email_token = AddAuth::Rails::Runtime.email.delivery_token(digest: AddAuthSignInToken.last.digest)
    previous = ActiveJob::Base.queue_adapter
    ActiveJob::Base.queue_adapter = :inline
    post "/passwords", params: {email_address: user.email_address}
    expect(response).to redirect_to("/session/new")
    message = ActionMailer::Base.deliveries.last
    expect(message.subject).to eq("Reset your password")
    link = URI.parse(message.body.decoded[/http[^\s]+/])
    get link.request_uri
    expect(response.status).to eq(200)
    token = link.path.split("/")[-2]
    put "/passwords/#{token}", params: {password: "replacement-password", password_confirmation: "replacement-password"}
    expect(response).to redirect_to("/session/new")
    expect(AddAuth::Rails::Runtime.sessions.resume(signed_value: initial.bearer)).to be_nil
    expect(User.find_by_password_reset_token(token)).to be_nil
    expect(AddAuth::Rails::Runtime.email.preview(token: old_email_token)).to be_nil
    expect(AddAuthSignInToken.last.delivery_payload).to be_nil
  ensure
    ActiveJob::Base.queue_adapter = previous if previous
  end
end
