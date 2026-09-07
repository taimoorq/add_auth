# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Authentication lifecycle hardening", type: :request, database: true do
  let!(:user) { User.create!(email_address: "lifecycle@example.test", password: "correct-password") }
  let(:runtime) { AddAuth::Rails::Runtime }

  around do |example|
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    example.run
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  def csrf(path = "/sign-in")
    get path
    Nokogiri::HTML(response.body).at_css('meta[name="csrf-token"]')["content"]
  end

  def password_sign_in(path = "/sign-in/password", email: user.email_address, password: "correct-password")
    post path, params: {email_address: email, password: password, authenticity_token: csrf}
  end

  %w[/session /sign-in/password].each do |path|
    it "rejects a replaced cookie after re-login and logout through #{path}" do
      password_sign_in(path)
      expect(response.status).to eq(303)
      previous_cookie = cookies[:session_id]
      previous_row = Session.last
      password_sign_in(path)
      expect(response.status).to eq(303)
      expect(previous_row.reload.revoked_at).to be_present
      delete "/session", params: {authenticity_token: csrf}
      expect(response.status).to eq(303)
      cookies[:session_id] = previous_cookie
      Current.reset
      get "/"
      expect(response).to redirect_to("/sign-in")
    end
  end

  it "preserves the original browser on invalid password and revokes it on a successful account switch" do
    password_sign_in
    previous = Session.last
    other = User.create!(email_address: "switch@example.test", password: "other-password")
    password_sign_in(email: other.email_address, password: "wrong")
    expect(response.status).to eq(422)
    expect(previous.reload.revoked_at).to be_nil
    password_sign_in(email: other.email_address, password: "other-password")
    expect(response.status).to eq(303)
    expect(previous.reload.revoked_at).to be_present
    expect(Session.last.user_id).to eq(other.id)
  end

  it "delivers and confirms an explicit email account switch and retires the old cookie" do
    password_sign_in
    old_cookie = cookies[:session_id]
    old_session = Session.last
    other = User.create!(email_address: "email-switch@example.test", password: "other-password")
    adapter = ActiveJob::Base.queue_adapter
    ActiveJob::Base.queue_adapter = :inline
    post "/sign-in/email", params: {email_address: other.email_address, authenticity_token: csrf}
    url = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    form_token = csrf(url.request_uri)
    expect(old_session.reload.revoked_at).to be_nil
    post "/sign-in/link", params: {token: token, switch_account: "1", authenticity_token: form_token}
    expect(response.status).to eq(303)
    expect(Session.last.user_id).to eq(other.id)
    expect(old_session.reload.revoked_at).to be_present
    cookies[:session_id] = old_cookie
    Current.reset
    get "/"
    expect(response).to redirect_to("/sign-in")
  ensure
    ActiveJob::Base.queue_adapter = adapter if adapter
  end

  it "invalidates delivered links on a host password reset while email sign-in is disabled" do
    adapter = ActiveJob::Base.queue_adapter
    ActiveJob::Base.queue_adapter = :inline
    post "/sign-in/email", params: {email_address: user.email_address, authenticity_token: csrf}
    url = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
    token = URI.decode_www_form(url.query).to_h.fetch("token")
    config = AddAuth.configuration
    enabled = config.email_link.enabled
    config.email_link.enabled = false
    reset = user.password_reset_token
    put "/passwords/#{reset}", params: {password: "replacement-password", password_confirmation: "replacement-password", authenticity_token: csrf}
    expect(response.status).to eq(302).or eq(303)
    expect(user.reload.authenticate("replacement-password")).to be_truthy
    config.email_link.enabled = true
    post "/sign-in/link", params: {token: token, authenticity_token: csrf}
    expect(response.status).to eq(422)
    expect(Session.count).to eq(0)
    expect(AddAuthSignInToken.last.revoked_at).to be_present
  ensure
    config.email_link.enabled = enabled if config
    ActiveJob::Base.queue_adapter = adapter if adapter
  end

  it "keeps a link revoked when the address changes away and back while email is disabled" do
    runtime.email.issue(identifier: user.email_address)
    record = AddAuthSignInToken.last
    raw = runtime.email.delivery_token(digest: record.digest)
    config = AddAuth.configuration
    enabled = config.email_link.enabled
    config.email_link.enabled = false
    old_address = user.email_address
    user.update!(email_address: "changed@example.test")
    user.update!(email_address: old_address)
    config.email_link.enabled = true
    expect(runtime.email.preview(token: raw)).to be_nil
    expect(record.reload.delivery_payload).to be_nil
  ensure
    config.email_link.enabled = enabled if config
  end

  it "denies an in-flight revoke after another request revoked the initiating bearer" do
    password_sign_in
    initiating = Session.last
    other = runtime.sessions.start(user: user, method: :password).session
    token = csrf
    allow_any_instance_of(AddAuth::Core::Sessions).to receive(:revoke_one).and_wrap_original do |original, **args|
      initiating.update!(revoked_at: Time.current)
      original.call(**args)
    end
    delete "/sessions/#{other.id}", params: {authenticity_token: token}
    expect(response.status).to eq(404)
    expect(other.reload.revoked_at).to be_nil
  end
end
