# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Session management", type: :request, database: true do
  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }

  def sign_in(email: user.email_address, password: "correct-password")
    post "/session", params: {email_address: email, password: password}
    expect(response).to have_http_status(:redirect)
    Session.last
  end

  it "lists only the current account's active sessions without bearer material" do
    current = sign_in
    other = User.create!(email_address: "other@example.test", password: "other-password")
    foreign = AddAuth::Rails::Runtime.sessions.start(user: other, method: :password, user_agent: "Foreign/1")
    own = AddAuth::Rails::Runtime.sessions.start(user: user, method: :email_link, user_agent: "Second/2")

    get "/sessions"
    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(response.headers["Referrer-Policy"]).to eq("no-referrer")
    expect(response.body).to include('name="turbo-cache-control" content="no-cache"')
    expect(response.body).to include("This browser", "Second/2")
    expect(response.body).not_to include("Foreign/1", own.session.token_digest, foreign.bearer)
    expect(response.body).not_to include("token_digest")
    expect(response.body).to include("/sessions/#{current.id}")

    get "/sessions", headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response).to have_http_status(:ok)
    expect(response.body).to include('target="add_auth-session-content"', "Second/2")
  end

  it "revokes another session and rejects its next request" do
    current = sign_in
    other = AddAuth::Rails::Runtime.sessions.start(user: user, method: :email_link, user_agent: "Other/2")
    delete "/sessions/#{other.session.id}"
    expect(response).to redirect_to("/sessions")
    expect(response).to have_http_status(:see_other)
    expect(other.session.reload.revoked_at).to be_present

    cookies[:session_id] = other.bearer
    get "/"
    expect(response).to redirect_to("/sign-in")
    expect(current.reload.revoked_at).to be_nil
  end

  it "signs out the current browser and does not allow cross-account revocation" do
    current = sign_in
    foreign_user = User.create!(email_address: "other@example.test", password: "other-password")
    foreign = AddAuth::Rails::Runtime.sessions.start(user: foreign_user, method: :password)

    delete "/sessions/#{foreign.session.id}"
    expect(response).to have_http_status(:not_found)
    expect(foreign.session.reload.revoked_at).to be_nil

    delete "/sessions/#{current.id}"
    expect(response).to redirect_to("/sign-in")
    expect(response).to have_http_status(:see_other)
    expect(current.reload.revoked_at).to be_present
    get "/sessions"
    expect(response).to redirect_to("/sign-in")
  end

  it "requires a fresh password proof before signing out every session" do
    current = sign_in
    other = AddAuth::Rails::Runtime.sessions.start(user: user, method: :email_link)

    get "/sessions/revoke-all"
    expect(response).to have_http_status(:ok)
    expect(response.body).to include("including this browser", "Current password")

    post "/sessions/revoke-all", params: {password: "wrong-password"}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(current.reload.revoked_at).to be_nil
    expect(other.session.reload.revoked_at).to be_nil

    post "/sessions/revoke-all", params: {password: "correct-password"}
    expect(response).to redirect_to("/sign-in")
    expect(response).to have_http_status(:see_other)
    expect(current.reload.revoked_at).to be_present
    expect(other.session.reload.revoked_at).to be_present
    expect(cookies[:session_id]).to be_blank
  end
  it "breaks session management out of a Turbo Frame without caching the authenticated page" do
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    get "/sessions", headers: {"Turbo-Frame" => "account"}
    expect(response.body).to include('name="turbo-visit-control" content="reload"', 'name="turbo-cache-control" content="no-cache"')
    expect(response.headers["Cache-Control"]).to include("no-store")
  end

  it "uses a 303 for an expired-session POST and never saves its unsafe return destination" do
    post "/sessions/revoke-all", params: {password: "correct-password"}
    expect(response.status).to eq(303)
    expect(response).to redirect_to("/sign-in")
  end
end
