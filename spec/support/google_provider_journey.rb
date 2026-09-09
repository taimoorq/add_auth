# frozen_string_literal: true

# Loaded only in the disposable Rails host built by spec/providers/google_sign_in.rb.
require "rspec/core"
require "rspec/expectations"
require "rspec/mocks"
require "webmock/rspec"
require "webrick"
require_relative "browser"
require_relative "mobile_callback_server"
require "socket"

WebMock.disable_net_connect!(allow_localhost: true)
Capybara.server_port = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }
Capybara.server_host = "localhost"
AddAuth.configuration.passkeys.rp_id = "localhost"
AddAuth.configuration.passkeys.origins = ["http://localhost:#{Capybara.server_port}"]
ActionController::Base.allow_forgery_protection = true
ActiveJob::Base.queue_adapter = :inline
raise "actual Google strategy required" if OmniAuth.config.test_mode
raise "host CSRF library was replaced" unless OmniAuth.config.request_validation_phase.is_a?(OmniAuth::RailsCsrfProtection::TokenVerifier)
RSpec.configure { |config|
  config.formatter = :documentation
  config.order = :defined
}

RSpec.describe "Actual Google provider journeys" do
  before do
    AddAuth.configuration.rate_limit_store.clear
    @key = OpenSSL::PKey::RSA.generate(2048)
    @subject = "google-existing-subject"
    @idp = WEBrick::HTTPServer.new(Port: ENV.fetch("GOOGLE_FIXTURE_PORT").to_i, BindAddress: "127.0.0.1",
      Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
    @idp.mount_proc("/authorize") do |request, response|
      uri = URI(request.query.fetch("redirect_uri"))
      uri.query = URI.encode_www_form(code: "synthetic-code", state: request.query.fetch("state"))
      response.status = 302
      response["Location"] = uri.to_s
    end
    @idp.mount_proc("/token") do |_request, response|
      now = Time.now.to_i
      jwt = JWT.encode({iss: "https://accounts.google.com", aud: "google-browser-fixture", sub: @subject,
                        iat: now, exp: now + 300}, @key, "RS256", kid: "google-fixture")
      response["Content-Type"] = "application/json"
      response.body = {access_token: "synthetic-access-token", token_type: "Bearer", id_token: jwt}.to_json
    end
    @thread = Thread.new { @idp.start }
    stub_request(:get, OmniAuth::Strategies::GoogleOauth2::USER_INFO_URL).to_return do
      {status: 200, body: {sub: @subject, email: "untrusted-profile@example.test"}.to_json, headers: {"Content-Type" => "application/json"}}
    end
    stub_request(:get, OmniAuth::Strategies::GoogleOauth2::JWKS_URL).to_return do
      {status: 200, body: {keys: [JWT::JWK.new(@key.public_key, kid: "google-fixture").export]}.to_json,
       headers: {"Content-Type" => "application/json"}}
    end
    stub_request(:post, "https://www.googleapis.com/oauth2/v3/tokeninfo").to_return do
      {status: 200, body: {aud: "google-browser-fixture", sub: @subject}.to_json, headers: {"Content-Type" => "application/json"}}
    end
  end

  after do
    @browser&.quit
    @idp&.shutdown
    @thread&.join
    @mobile_callback&.stop
  end

  def browser_for(mode)
    AddAuth.configuration.turbo_enabled = mode == :turbo
    @browser = Capybara::Session.new((mode == :no_js) ? :add_auth_no_js : :add_auth_chrome, Rails.application)
    @browser.visit "/sign-in"
    expect(@browser.evaluate_script("typeof window.Turbo")).to eq("undefined") if mode == :html
    @browser
  end

  def finish_google(heading = "Continue to Google")
    expect(@browser).to have_css("h1", text: heading)
    @browser.click_button "Continue with Google"
  end

  def email_verification(email, heading)
    expect(@browser).to have_css("h1", text: "Verify it’s you")
    expect(@browser).not_to have_button("Verify with Google")
    @browser.click_button "Email me a verification link"
    expect(@browser).to have_css("h1", text: "Check your email")
    message = ActionMailer::Base.deliveries.reverse.find { |mail| mail.to == [email] && mail.subject == "Verify your current session" }
    @browser.visit URI.parse(message.body.decoded.scan(%r{https://[^[:space:]<>]+}).first).request_uri
    @browser.click_button "Confirm verification"
    expect(@browser).to have_css("h1", text: heading)
  end

  def password_verification(password, heading)
    expect(@browser).to have_css("h1", text: "Verify it’s you")
    @browser.fill_in "Current password", with: password
    @browser.click_button "Verify with password"
    expect(@browser).to have_css("h1", text: heading)
  end

  %i[turbo html no_js].each do |mode|
    it "returns a single-use mobile handoff through the actual provider and HTTPS callback with #{mode}" do
      @subject = "mobile-#{mode}"
      user = User.create!(email_address: "#{@subject}@example.test", confirmed_at: Time.current)
      configuration = AddAuth.configuration.external_identities.provider("google").configuration
      AddAuthExternalIdentity.create!(user: user, namespace: configuration.namespace(@subject), provider_id: configuration.id,
        issuer: configuration.issuer, audience: configuration.audience, subject: @subject, provenance: "reviewed-mobile-import",
        credential_version: SecureRandom.hex(16), linked_at: Time.current - 60)
      @mobile_callback = MobileCallbackServer.new(port: ENV.fetch("MOBILE_CALLBACK_PORT").to_i)
      state = SecureRandom.urlsafe_base64(32)
      verifier = SecureRandom.urlsafe_base64(48)
      callback = AddAuth.configuration.mobile.callbacks.fetch("android")
      parameters = {client_id: "android", callback: callback, state: state,
                    code_challenge: Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false), code_challenge_method: "S256"}
      browser_for(mode)
      entry = "/mobile/providers/google_oauth2?#{URI.encode_www_form(parameters)}"
      if mode == :turbo
        @browser.execute_script(<<~JS, entry)
          const frame = document.createElement('turbo-frame');
          frame.id = 'mobile-auth'; frame.src = arguments[0]; document.body.appendChild(frame);
        JS
      else
        @browser.visit entry
      end
      finish_google
      expect(@browser).to have_css("h1", text: "Return to the app")
      destination = URI(@browser.current_url)
      expect(destination.to_s.split("?").first).to eq(callback)
      fields = URI.decode_www_form(destination.query)
      expect(fields.map(&:first)).to contain_exactly("code", "state")
      expect(fields.to_h.fetch("state")).to eq(state)
      code = fields.to_h.fetch("code")
      expect(code).to match(AddAuth::Core::MobileHandoffs::CODE)
      expect(Session.where(user_id: user.id)).to be_empty
      client = ActionDispatch::Integration::Session.new(Rails.application)
      exchange = {client_id: "android", code: code, state: state, code_verifier: "wrong" * 12}
      client.post "/mobile/handoff", params: exchange, as: :json
      expect(client.response.status).to eq(401)
      expect(Session.where(user_id: user.id)).to be_empty
      exchange[:code_verifier] = verifier
      client.post "/mobile/handoff", params: exchange, as: :json
      expect(client.response.status).to eq(201)
      expect(client.response.headers["Set-Cookie"]).to be_nil
      expect(client.response.parsed_body.fetch("token")).to match(AddAuth::Core::MobileProfile::PATTERN)
      expect(Session.where(user_id: user.id).sole).to have_attributes(transport: "mobile", client_id: "android")
      client.post "/mobile/handoff", params: exchange, as: :json
      expect(client.response.status).to eq(401)
      @browser.visit "/sessions"
      expect(@browser).to have_css("h1", text: "Sign in")
    end

    it "preserves an existing binding and remembered choice with #{mode}" do
      user = User.find_or_create_by!(email_address: "existing@example.test") { |row| row.confirmed_at = Time.current }
      configuration = AddAuth.configuration.external_identities.provider("google").configuration
      binding = AddAuthExternalIdentity.find_or_create_by!(namespace: configuration.namespace(@subject)) do |row|
        row.assign_attributes(user_id: user.id, provider_id: "google", issuer: configuration.issuer, audience: configuration.audience,
          subject: @subject, provenance: "reviewed-fixture-import", credential_version: SecureRandom.hex(16), linked_at: Time.current - 60)
      end
      browser_for(mode)
      @browser.within('form[action="/sign-in/providers/google_oauth2"]') do
        @browser.check "Keep me signed in on this browser"
        @browser.click_button "Continue with Google"
      end
      finish_google
      expect(@browser).to have_text("Signed in as existing@example.test")
      row = Session.where(user_id: user.id).order(:id).last
      expect(row.authenticated_with).to eq("external_identity")
      expect(row.remembered).to be(true)
      expect(binding.reload.user_id).to eq(user.id)
      expect(user.reload.email_address).to eq("existing@example.test")
      expect(user.password_digest).to be_nil
    end

    it "enrolls, confirms, recovers, links/unlinks and deletes with #{mode}" do
      @subject = "new-#{mode}"
      email = "#{@subject}@example.test"
      browser_for(mode)
      @browser.visit "/account/sign-up/providers/google_oauth2"
      @browser.fill_in "Email address", with: email
      @browser.click_button "Continue with Google"
      finish_google
      expect(@browser).to have_css("h1", text: "Check your email")
      user = User.find_by!(email_address: email)
      expect(user.password_digest).to be_nil
      expect(user.confirmed_at).to be_nil
      expect(Session.where(user_id: user.id)).to be_empty
      expect(AddAuthExternalIdentity.find_by!(user_id: user.id).subject).to eq(@subject)
      proof = AddAuthExternalTransaction.where(purpose: "enroll_external_identity").order(:id).last
      expect(proof.enrollment_payload).to be_nil
      expect(proof.consumed_at).to be_present
      message = ActionMailer::Base.deliveries.reverse.find { |mail| mail.to == [email] }
      expect(message.subject).to eq("Confirm your email address")
      @browser.visit URI.parse(message.body.decoded.scan(%r{https://[^[:space:]<>]+}).first).request_uri
      @browser.click_button "Confirm this email address"
      expect(@browser).to have_css("h1", text: "Sign in")
      expect(Session.where(user_id: user.id)).to be_empty
      @browser.click_button "Continue with Google"
      finish_google
      expect(@browser).to have_text("Signed in as #{email}")
      expect(Session.where(user_id: user.id).last.authenticated_with).to eq("external_identity")
      expect(user.reload.email_address).to eq(email)

      # Ordinary provider SSO supplies no fresh-purpose proof. A provider-only
      # account uses its independently confirmed email to add its first password.
      password = "provider-new-password"
      @browser.visit "/account/password"
      @browser.fill_in "New password", with: password
      @browser.click_button "Change password"
      email_verification(email, "Change your password")
      @browser.fill_in "New password", with: password
      @browser.click_button "Change password"
      expect(@browser).to have_css("h1", text: "Sign in")
      expect(user.reload.authenticate(password)).to eq(user)
      expect(Session.where(user_id: user.id, revoked_at: nil)).to be_empty
      @browser.click_button "Continue with Google"
      finish_google
      expect(@browser).to have_text("Signed in as #{email}")

      @browser.visit "/account/external-identities"
      @browser.find("summary", text: "Remove this sign-in method").click
      @browser.click_button "Confirm removal"
      password_verification(password, "External sign-in methods")
      @browser.find("summary", text: "Remove this sign-in method").click
      @browser.click_button "Confirm removal"
      expect(@browser).to have_css("h1", text: "Sign in")
      binding = AddAuthExternalIdentity.find_by!(user_id: user.id)
      expect(binding.revoked_at).to be_present
      expect(Session.where(user_id: user.id, revoked_at: nil)).to be_empty

      @browser.fill_in "Email address", with: email
      @browser.fill_in "Password", with: password
      @browser.click_button "Sign in with password"
      expect(@browser).to have_css("h1", text: "External sign-in methods")
      expect(Session.where(user_id: user.id, revoked_at: nil).last.authenticated_with).to eq("password")
      @browser.click_button "Link Google"
      password_verification(password, "External sign-in methods")
      @browser.click_button "Link Google"
      finish_google("Confirm with Google")
      expect(@browser).to have_css("h1", text: "External sign-in methods")
      expect(binding.reload.revoked_at).to be_nil
      expect(binding.user_id).to eq(user.id)

      @browser.visit "/account/delete"
      @browser.click_button "Delete my account"
      password_verification(password, "Delete your account")
      expect(User.uncached { User.exists?(user.id) }).to be(true)
      @browser.click_button "Delete my account"
      expect(@browser).to have_css("h1", text: "Sign in")
      expect(User.uncached { User.exists?(user.id) }).to be(false)
      expect(AddAuthExternalIdentity.where(user_id: user.id)).to be_empty
      expect(Session.where(user_id: user.id)).to be_empty
    end
  end
end

exit RSpec::Core::Runner.new(RSpec::Core::ConfigurationOptions.new([])).run_specs(RSpec.world.ordered_example_groups)
