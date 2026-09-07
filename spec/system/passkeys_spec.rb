# frozen_string_literal: true

require "rails_helper"
require_relative "../support/browser"
require_relative "../support/passkey_runtime"

RSpec.describe "Passkey browser journeys", database: true do
  include_context "passkey runtime"
  let!(:user) { User.create!(email_address: "browser-passkey@example.test", password: "correct-password") }

  around do |example|
    csrf = ActionController::Base.allow_forgery_protection
    adapter = ActiveJob::Base.queue_adapter
    ActionController::Base.allow_forgery_protection = true
    example.run
  ensure
    ActionController::Base.allow_forgery_protection = csrf
    ActiveJob::Base.queue_adapter = adapter
  end

  before { ActiveJob::Base.queue_adapter = :inline }

  def browser_with_authenticator(conditional: false)
    browser = Capybara::Session.new(:add_auth_chrome, Rails.application)
    @origin = "http://localhost:#{browser.server.port}"
    AddAuth.configuration.passkeys.origins = [@origin]
    unless conditional
      # Model a capable browser without conditional mediation; verification
      # still uses the actual native WebAuthn API and virtual authenticator.
      browser.driver.browser.execute_cdp("Page.addScriptToEvaluateOnNewDocument",
        source: "Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', {value: async () => false, configurable: true})")
    end
    @virtual = browser.driver.browser.add_virtual_authenticator(Selenium::WebDriver::VirtualAuthenticatorOptions.new(
      protocol: :ctap2, transport: :internal, resident_key: true, user_verification: true, user_verified: true
    ))
    browser
  end

  def visit(browser, path) = browser.visit("#{@origin}#{path}")

  def password_sign_in(browser)
    visit(browser, "/sign-in")
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "correct-password"
    browser.click_button "Sign in with password"
    expect(browser).to have_text("Signed in")
  end

  def enroll(browser)
    password_sign_in(browser)
    visit(browser, "/passkeys")
    browser.click_button "Add a passkey"
    expect(browser).to have_text("Verify it’s you")
    browser.fill_in "Current password", with: "correct-password"
    browser.click_button "Verify with password"
    expect(browser).to have_text("Your passkeys")
    browser.click_button "Add a passkey"
    expect(browser).to have_css("h2", text: "Passkey", exact_text: true)
    expect(AddAuthCredential.count).to eq(1)
  end

  it "enrolls, renames, signs in, verifies and activates strict policy using the native browser API" do
    browser = browser_with_authenticator
    enroll(browser)
    expect(ActionMailer::Base.deliveries.last.body.decoded).to include("A passkey was added")
    browser.fill_in "Passkey name", with: "My security key"
    browser.click_button "Rename"
    expect(browser).to have_css("h2", text: "My security key")
    visit(browser, "/sessions")
    browser.click_button "Sign out", exact: true
    expect(browser).to have_css("h1", text: "Sign in", exact_text: true)
    browser.click_button "Sign in with a passkey"
    expect(browser).to have_text("Signed in")
    expect(Session.last.authenticated_with).to eq("passkey")
    visit(browser, "/passkeys")
    browser.click_link "Verify to change policy"
    browser.click_button "Verify with a passkey"
    expect(browser).to have_text("Your passkeys")
    browser.check "I understand the recovery limits and have tested another way to access my account."
    browser.click_button "Require passkeys for this account"
    expect(browser).to have_text("Strict: passkeys are required")
    expect(user.reload.add_auth_strict).to be(true)
    @virtual.remove!
    visit(browser, "/sessions")
    browser.click_button "Sign out", exact: true
    expect(browser).to have_css("h1", text: "Sign in", exact_text: true)
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "correct-password"
    browser.click_button "Sign in with password"
    expect(browser).to have_css('[role="alert"]', text: "Email or password is incorrect")
  ensure
    warn browser.driver.browser.logs.get(:browser).map(&:message).join("\n") if browser && RSpec.current_example.exception
    browser&.quit
  end

  it "uses conditional mediation through the same verified sign-in endpoint" do
    browser = browser_with_authenticator(conditional: true)
    enroll(browser)
    visit(browser, "/sessions")
    browser.click_button "Sign out", exact: true
    expect(browser).to have_current_path("/")
    expect(browser).to have_text("Signed in")
    expect(Session.last.authenticated_with).to eq("passkey")
    expect(AddAuthCredential.last.last_used_at).to be_present
  ensure
    browser&.quit
  end

  it "completes explicit delivered-mail recovery on a replacement authenticator" do
    browser = browser_with_authenticator
    enroll(browser)
    lost = AddAuthCredential.last
    visit(browser, "/sessions")
    browser.click_button "Sign out", exact: true
    expect(browser).to have_css("h1", text: "Sign in", exact_text: true)
    @virtual.remove!
    @virtual = browser.driver.browser.add_virtual_authenticator(Selenium::WebDriver::VirtualAuthenticatorOptions.new(
      protocol: :ctap2, transport: :internal, resident_key: true, user_verification: true, user_verified: true
    ))
    visit(browser, "/recover")
    browser.fill_in "Recovery email address", with: user.email_address
    browser.click_button "Send recovery link"
    expect(browser).to have_text("Check your email")
    link = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
    visit(browser, link.request_uri)
    browser.click_button "Continue recovering this account"
    expect(browser).to have_text("Your passkeys")
    browser.click_button "Add a passkey"
    expect(browser).to have_css("section[id^='passkey_']", count: 2)
    expect(lost.reload.revoked_at).to be_nil
    expect(ActionMailer::Base.deliveries.last.body.decoded).to include("Passkey recovery completed")
  ensure
    warn browser.driver.browser.logs.get(:browser).map(&:message).join("\n") if browser && RSpec.current_example.exception
    browser&.quit
  end

  it "shows an honest no-JS unavailable state and keeps permitted password access usable" do
    browser = Capybara::Session.new(:add_auth_no_js, Rails.application)
    @origin = "http://localhost:#{browser.server.port}"
    AddAuth.configuration.passkeys.origins = [@origin]
    password_sign_in(browser)
    visit(browser, "/passkeys")
    expect(browser).to have_text("Passkeys need JavaScript and a compatible browser")
    expect(browser).not_to have_button("Add a passkey")
    visit(browser, "/reauthenticate?purpose=manage_policy")
    expect(browser).to have_text("Passkeys need JavaScript")
    expect(browser).not_to have_button("Verify with password")
  ensure
    browser&.quit
  end
end
