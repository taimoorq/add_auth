# frozen_string_literal: true

require "rails_helper"
require_relative "../support/browser"

RSpec.describe "Sign-in browser journeys", database: true do
  around do |example|
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    example.run
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }

  def capture(browser, name)
    return unless ENV["ADD_AUTH_SCREENSHOTS"]
    FileUtils.mkdir_p(ENV.fetch("ADD_AUTH_SCREENSHOTS"))
    browser.save_screenshot(File.join(ENV.fetch("ADD_AUTH_SCREENSHOTS"), "#{name}.png"))
  end

  it "supports failure/success, responsive layout, focus and the configured navigation mode" do
    browser = Capybara::Session.new(:add_auth_chrome, Rails.application)
    browser.visit "/sign-in"
    expect(browser).to have_css(".add_auth-panel")
    browser.document.synchronize do
      raise Capybara::ElementNotFound unless browser.evaluate_script("typeof window.Turbo") == (AddAuth.configuration.turbo_enabled ? "object" : "undefined")
    end
    browser.execute_script("window.addAuthNavigationMarker = true")
    capture(browser, "sign-in-desktop")
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "wrong"
    browser.click_button "Sign in with password"
    expect(browser).to have_css('[role="alert"]', text: "Email or password is incorrect")
    expect(browser.evaluate_script("window.addAuthNavigationMarker === true")).to eq(AddAuth.configuration.turbo_enabled)
    browser.current_window.resize_to(390, 844)
    expect(browser.evaluate_script("window.innerWidth")).to be <= 500
    expect(browser.evaluate_script("document.documentElement.scrollWidth <= window.innerWidth")).to be(true)
    browser.find("#email_address").send_keys(:tab)
    expect(browser.evaluate_script("getComputedStyle(document.activeElement).outlineStyle")).to eq("solid")
    capture(browser, "sign-in-mobile-error")
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "correct-password"
    browser.click_button "Sign in with password"
    expect(browser).to have_text("Signed in")
    # A frame that redirects to authentication must become a full-page visit.
    if AddAuth.configuration.turbo_enabled
      Session.update_all(revoked_at: Time.current)
      browser.visit "/sign-in"
      browser.document.synchronize do
        raise Capybara::ElementNotFound unless browser.evaluate_script("typeof window.Turbo") == "object"
      end
      browser.execute_script('document.body.innerHTML = \'<turbo-frame id="account" src="/"></turbo-frame>\'')
      expect(browser).to have_css("h1", text: "Sign in")
      expect(browser).not_to have_text("Content missing")
    else
      expect(browser.evaluate_script("typeof window.Turbo")).to eq("undefined")
    end
    errors = browser.driver.browser.logs.get(:browser).select { |entry| entry.level == "SEVERE" && !entry.message.include?("favicon.ico") && !entry.message.include?("422") }
    expect(errors.map(&:message)).to be_empty
  ensure
    warn browser.driver.browser.logs.get(:browser).map(&:message).join("\n") if browser && RSpec.current_example.exception
    browser&.quit
  end

  it "requests and confirms a delivered link on another browser with JavaScript disabled" do
    requester = Capybara::Session.new(:add_auth_no_js, Rails.application)
    receiver = Capybara::Session.new(:add_auth_no_js, Rails.application)
    previous_adapter = ActiveJob::Base.queue_adapter
    ActiveJob::Base.queue_adapter = :inline
    requester.visit "/sign-in"
    requester.fill_in "Email me a sign-in link", with: user.email_address
    requester.click_button "Send sign-in link"
    expect(requester).to have_text("Check your email")
    url = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
    receiver.visit url.request_uri
    expect(receiver).to have_text("Confirm your sign-in")
    expect(Session.count).to eq(0)
    capture(receiver, "email-confirmation-no-js")
    receiver.click_button "Sign in to this account"
    expect(receiver).to have_text("Signed in")
    requester.visit "/"
    expect(requester).to have_css("h1", text: "Sign in")
    receiver.visit url.request_uri
    expect(receiver).to have_text("Request a new link")
    requester.fill_in "Email address", with: user.email_address
    requester.fill_in "Password", with: "correct-password"
    requester.click_button "Sign in with password"
    expect(requester).to have_text("Signed in")
  ensure
    ActiveJob::Base.queue_adapter = previous_adapter if previous_adapter
    requester&.quit
    receiver&.quit
  end

  %i[add_auth_chrome add_auth_no_js].each do |driver|
    it "keeps a delivered bound link usable only in its requesting browser with #{driver}" do
      original_binding = AddAuth.configuration.email_link.same_browser
      AddAuth.configuration.email_link.same_browser = true
      previous_adapter = ActiveJob::Base.queue_adapter
      ActiveJob::Base.queue_adapter = :inline
      requester = Capybara::Session.new(driver, Rails.application)
      receiver = Capybara::Session.new(driver, Rails.application)
      requester.visit "/sign-in"
      requester.fill_in "Email me a sign-in link", with: user.email_address
      requester.click_button "Send sign-in link"
      expect(requester).to have_text("Check your email")
      url = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
      receiver.visit url.request_uri
      expect(receiver).to have_text("Open this link in the requesting browser")
      expect(receiver).not_to have_button("Sign in to this account")
      expect(AddAuthSignInToken.last.consumed_at).to be_nil
      requester.visit url.request_uri
      requester.click_button "Sign in to this account"
      expect(requester).to have_text("Signed in")
      receiver.visit "/"
      expect(receiver).to have_css("h1", text: "Sign in")
      expect(Session.count).to eq(1)
    ensure
      AddAuth.configuration.email_link.same_browser = original_binding
      ActiveJob::Base.queue_adapter = previous_adapter if previous_adapter
      requester&.quit
      receiver&.quit
    end
  end

  it "reviews and revokes a session with JavaScript disabled" do
    browser = Capybara::Session.new(:add_auth_no_js, Rails.application)
    browser.visit "/sign-in"
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "correct-password"
    browser.click_button "Sign in with password"
    expect(browser).to have_text("Signed in")

    other = AddAuth::Rails::Runtime.sessions.start(user: user, method: :email_link, user_agent: "Other browser/2")
    browser.visit "/sessions"
    expect(browser).to have_text("Your sessions")
    expect(browser).to have_text("Other browser/2")
    browser.find("form[action='/sessions/#{other.session.id}']").click_button "Revoke"
    # Wait for the specific removed row; the page heading also existed before
    # submission and therefore cannot establish that navigation has finished.
    expect(browser).to have_no_css("#session_#{other.session.id}")
    expect(other.session.reload.revoked_at).to be_present
    browser.visit "/sessions/revoke-all"
    browser.fill_in "Current password", with: "wrong"
    browser.click_button "Sign out everywhere"
    expect(browser).to have_css('[role="alert"]')
    browser.fill_in "Current password", with: "correct-password"
    browser.click_button "Sign out everywhere"
    expect(browser).to have_css("h1", text: "Sign in")
    expect(Session.where(revoked_at: nil).count).to eq(0)
  ensure
    browser&.quit
  end

  %i[add_auth_chrome add_auth_no_js].each do |driver|
    it "rejects the previous browser cookie after a replacement login and logout with #{driver}" do
      browser = Capybara::Session.new(driver, Rails.application)
      previous_cookie = nil
      2.times do |attempt|
        browser.visit "/sign-in"
        browser.fill_in "Email address", with: user.email_address
        browser.fill_in "Password", with: "correct-password"
        browser.click_button "Sign in with password"
        expect(browser).to have_text("Signed in")
        previous_cookie = browser.driver.browser.manage.cookie_named("session_id") if attempt.zero?
      end
      expect(Session.where(revoked_at: nil).count).to eq(1)
      browser.visit "/sessions"
      browser.click_button "Sign out", exact: true
      expect(browser).to have_css("h1", text: "Sign in")
      browser.driver.browser.manage.add_cookie(previous_cookie)
      browser.visit "/"
      expect(browser).to have_css("h1", text: "Sign in")
      expect(Session.where(revoked_at: nil).count).to eq(0)
    ensure
      browser&.quit
    end
  end
end
