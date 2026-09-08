# frozen_string_literal: true

require "rails_helper"
require_relative "../support/passkey_runtime"

RSpec.describe "Passwordless and public Rails hosts", type: :request, database: true do
  include_context "passkey runtime"
  let(:runtime) { AddAuth::Rails::Runtime }

  around do |example|
    config = AddAuth.configuration
    previous = config.passwords_enabled
    config.passwords_enabled = false
    example.run
  ensure
    config.passwords_enabled = previous
  end

  it "guards stock password aliases when passwordless mode is set before boot" do
    require "open3"
    script = <<~SCRIPT
      require "add_auth"
      AddAuth.configuration.passwords_enabled = false
      require_relative "spec/dummy/config/environment"
      abort "password entry unguarded" unless SessionsController.ancestors.include?(AddAuth::Rails::PasswordEntry)
      abort "authentication missing" unless ApplicationController.ancestors.include?(AddAuth::Rails::Authentication)
      def User.authenticate_by(*) = abort("disabled password verifier reached")
      client = ActionDispatch::Integration::Session.new(Rails.application)
      client.get "/session/new"
      abort "stock form unavailable" unless client.response.status == 200
      abort "password form exposed" if client.response.body.include?('name="password"')
      %w[/session /sign-in/password].each do |path|
        client.post path, params: {email_address: "disabled@example.test", password: "unused"}
        abort "password alias accepted" unless client.response.status == 404
      end
    SCRIPT
    output, status = Open3.capture2e({"RAILS_ENV" => "test"}, RbConfig.ruby, "-Ilib", "-e", script,
      chdir: File.expand_path("../..", __dir__))
    expect(status.success?).to be(true), output
  end

  it "rejects every password entry and proof even for an existing password account" do
    user = User.create!(email_address: "disabled-password@example.test", password: "correct-password")
    expect(User).not_to receive(:authenticate_by)
    %w[/session /sign-in/password].each do |path|
      post path, params: {email_address: user.email_address, password: "correct-password"}
      expect(response).to have_http_status(:not_found)
    end
    expect(runtime.sessions.start(user: user, method: :password)).to be_nil
    grant = runtime.sessions.start(user: user, method: :email_link)
    expect(grant).to be_present
    expect(runtime.reauthenticate(user: user, session: grant.session, password: "correct-password",
      ip: "127.0.0.1", challenge_token: nil)).not_to be_success
    expect(runtime.elevate_password(user: user, session: grant.session, purpose: :manage_passkeys,
      password: "correct-password", ip: "127.0.0.1", challenge_token: nil)).not_to be_success
    get "/sign-in"
    expect(response.body).not_to include('name="password"')
    expect(response.body).to include('name="email_address"')
    expect(Session.count).to eq(1)
  end

  it "boots an email host that omits the conventional password controller" do
    require "open3"
    script = <<~SCRIPT
      require "add_auth"
      AddAuth.configuration.passwords_enabled = false
      require_relative "spec/dummy/config/application"
      Rails.autoloaders.main.ignore(Rails.root.join("app/controllers/sessions_controller.rb"))
      require_relative "spec/dummy/config/environment"
      abort "password controller loaded" if defined?(::SessionsController)
      client = ActionDispatch::Integration::Session.new(Rails.application)
      client.get "/sign-in"
      abort "email entry unavailable" unless client.response.status == 200
      abort "password form exposed" if client.response.body.include?('name="password"')
      abort "email form missing" unless client.response.body.include?("Send sign-in link")
      client.post "/sign-in/password", params: {email_address: "disabled@example.test", password: "unused"}
      abort "password entry accepted" unless client.response.status == 404
    SCRIPT
    output, status = Open3.capture2e({"RAILS_ENV" => "test"}, RbConfig.ruby, "-Ilib", "-e", script,
      chdir: File.expand_path("../..", __dir__))
    expect(status.success?).to be(true), output
  end

  it "uses ordinary passwordless models and invalidates address-bound proofs on email change" do |example|
    # Rails association reflections retain their resolved User class after
    # RSpec restores a stubbed constant. Isolate this alternate host model so
    # later requests cannot inherit its passwordless association cache.
    unless ENV["ADD_AUTH_ISOLATED_HOST_SPEC"] == example.id
      require "open3"
      output, status = Open3.capture2e({"ADD_AUTH_ISOLATED_HOST_SPEC" => example.id},
        RbConfig.ruby, "-S", "bundle", "exec", "rspec", example.id,
        chdir: File.expand_path("../..", __dir__))
      expect(status.success?).to be(true), output
      next
    end

    existing = User.create!(email_address: "passwordless@example.test", password: "unused-fixture-password")
    passwordless = Class.new(ApplicationRecord) do
      self.table_name = "users"
      self.ignored_columns = ["password_digest"]
      has_many :sessions, foreign_key: :user_id
      include AddAuth::Rails::UserLifecycle

      normalizes :email_address, with: ->(email) { email.strip.downcase }
    end
    stub_const("User", passwordless)
    user = User.find(existing.id)
    expect(user).not_to respond_to(:password_digest)
    expect(user).not_to respond_to(:saved_change_to_password_digest?)
    expect(runtime.sessions.start(user: user, method: :password)).to be_nil
    grant = runtime.sessions.start(user: user, method: :email_link)
    runtime.email.issue(identifier: user.email_address)
    token = AddAuthSignInToken.last
    raw = runtime.email.delivery_token(digest: token.digest)
    expect(runtime.email.preview(token: raw)).to be_present
    user.update!(email_address: "updated@example.test")
    expect(grant.session.reload.revoked_at).to be_present
    expect(runtime.email.preview(token: raw)).to be_nil
    expect(token.reload.delivery_payload).to be_nil
    expect(AddAuthSecurityEvent.where(user_id: user.id, kind: "email_changed").count).to eq(2)
  end

  it "requires named authentication on private management actions when the host serves public pages" do
    allow_any_instance_of(ApplicationController).to receive(:require_authentication).and_return(true)
    %w[/sessions /sessions/revoke-all /passkeys /reauthenticate?purpose=manage_passkeys].each do |path|
      get path
      expect(response).to redirect_to("/sign-in")
    end
    post "/passkeys/options", as: :json
    expect(response).to redirect_to("/sign-in")
    expect(AddAuthCeremony.count).to eq(0)
  end

  it "keeps anonymous passkey, recovery and emailed confirmation entry points public" do
    host! "localhost"
    post "/passkeys/sign-in/options", as: :json
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to have_key("transaction")
    get "/recover"
    expect(response).to have_http_status(:ok)
    get "/reauthenticate/link", params: {token: "invalid"}
    expect(response).to have_http_status(:ok)
    expect(response.body).to include("link")
    post "/reauthenticate/link", params: {token: "invalid"}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(Session.count).to eq(0)
  end
end
