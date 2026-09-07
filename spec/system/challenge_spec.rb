# frozen_string_literal: true

require "rails_helper"
require_relative "../support/browser"

RSpec.describe "Challenge browser lifecycle", database: true do
  let!(:user) { User.create!(email_address: "challenge@example.test", password: "correct-password") }
  around do |example|
    config = Latchkey.configuration
    previous = [config.challenge, config.challenge_on, ActionController::Base.allow_forgery_protection]
    config.challenge_on = %i[sign_in email_link]
    ActionController::Base.allow_forgery_protection = true
    example.run
    if example.exception && @browser
      warn @browser.text
      warn @browser.driver.browser.logs.get(:browser).map(&:message).join("\n")
    end
  ensure
    config.challenge, config.challenge_on, ActionController::Base.allow_forgery_protection = previous
    @browser&.quit
  end

  def browser_for(mode, source)
    config = Latchkey.configuration
    used = []
    transport = lambda do |**args|
      token = args.fetch(:params).fetch("response")
      action = token.split(":")[1]
      valid = !used.include?(token)
      used << token
      [200, JSON.generate(success: valid, action: action, hostname: "example.test", score: 0.9)]
    end
    config.challenge = if mode == :turnstile
      Latchkey::Core::Challenge::Turnstile.new(site_key: "site", secret_key: "test-only", transport: transport)
    else
      Latchkey::Core::Challenge::Recaptcha.new(site_key: "site", secret_key: "test-only", version: mode, transport: transport)
    end
    allow(config.challenge).to receive(:script_url).and_return(nil)
    @browser = Capybara::Session.new(:latchkey_chrome, Rails.application)
    @browser.driver.browser.execute_cdp("Page.addScriptToEvaluateOnNewDocument", source: source)
    @browser.visit "/sign-in"
    @browser
  end

  def wait_for(script)
    @browser.document.synchronize { raise Capybara::ElementNotFound unless @browser.evaluate_script(script) }
  end

  it "obtains fresh v3 tokens on both forms after Turbo failures and a late provider readiness callback" do
    browser = browser_for(:v3, <<~JS)
      window.proofs = 0;
      window.readiness = [];
      window.grecaptcha = {
        ready(callback) { window.readiness.push(callback) },
        execute(key, {action}) { return Promise.resolve(`proof:${action}:${++window.proofs}`) }
      };
    JS
    wait_for("window.readiness.length === 2")
    expect(browser).to have_button("Sign in with password", disabled: true)
    browser.execute_script("window.grecaptcha.ready = callback => callback(); window.readiness.forEach(callback => callback())")
    2.times do
      browser.fill_in "Email address", with: user.email_address
      browser.fill_in "Password", with: "wrong"
      browser.click_button "Sign in with password"
      expect(browser).to have_css('[role="alert"]', text: "Email or password is incorrect")
      expect(browser).to have_field("Password", with: "")
      expect(browser).to have_field("Email address", with: user.email_address)
      expect(browser).to have_button("Sign in with password", disabled: false)
    end
    expect(browser.evaluate_script("window.proofs")).to eq(2)
    browser.fill_in "Email me a sign-in link", with: user.email_address
    browser.click_button "Send sign-in link"
    expect(browser).to have_text("Check your email")
    expect(ActiveJob::Base.queue_adapter.enqueued_jobs.size).to eq(1)
    expect(Session.count).to eq(0)
  end

  %i[v2 turnstile].each do |mode|
    it "renders both #{mode} widgets explicitly and removes spent tokens on replacement" do
      browser = browser_for(mode, <<~JS)
        window.widgets = [];
        const provider = {
          render(element, options) { const id = window.widgets.length; window.widgets.push({element, options}); return id },
          reset(id) { window.widgets[id].options["expired-callback"]() },
          remove(id) { window.widgets[id].removed = true }
        };
        window.grecaptcha = provider;
        window.turnstile = provider;
      JS
      wait_for("window.widgets.length === 2")
      expect(browser).to have_button("Sign in with password", disabled: true)
      expect(browser).to have_button("Send sign-in link", disabled: true)
      browser.execute_script('window.widgets[0].options.callback("proof:sign_in:1")')
      browser.fill_in "Email address", with: user.email_address
      browser.fill_in "Password", with: "wrong"
      browser.click_button "Sign in with password"
      expect(browser).to have_css('[role="alert"]', text: "Email or password is incorrect")
      wait_for("window.widgets.length === 4")
      expect(browser).to have_button("Sign in with password", disabled: true)
      browser.execute_script('window.widgets[2].options.callback("proof:sign_in:2")')
      browser.fill_in "Password", with: "correct-password"
      browser.click_button "Sign in with password"
      expect(browser).to have_text("Signed in")
      expect(Session.count).to eq(1)
    end
  end

  it "ignores late v3 completion after navigation and clears live tokens before caching" do
    browser = browser_for(:v3, <<~JS)
      window.pendingProofs = [];
      window.grecaptcha = { ready(callback) { callback() }, execute() { return new Promise(resolve => window.pendingProofs.push(resolve)) } };
    JS
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "correct-password"
    browser.click_button "Sign in with password"
    wait_for("window.pendingProofs.length === 1")
    browser.execute_script('window.Turbo.visit("/sign-in?retry=1")')
    expect(browser).to have_current_path("/sign-in?retry=1")
    expect(browser).to have_field("Password", with: "")
    browser.execute_script('window.pendingProofs[0]("proof:sign_in:old")')
    expect(browser).to have_button("Sign in with password", disabled: false)
    expect(Session.count).to eq(0)
    browser.execute_script('document.querySelectorAll("[name=challenge_token]").forEach(field => field.value = "sensitive"); document.dispatchEvent(new Event("turbo:before-cache"))')
    expect(browser.evaluate_script('Array.from(document.querySelectorAll("[name=challenge_token]")).every(field => field.value === "")')).to be(true)
  end

  it "gives an honest server rejection with JavaScript disabled" do
    Latchkey.configuration.challenge = Latchkey::Core::Challenge::Test.new(mode: :rejected)
    @browser = Capybara::Session.new(:latchkey_no_js, Rails.application)
    @browser.visit "/session/new"
    @browser.fill_in "Email address", with: user.email_address
    @browser.fill_in "Password", with: "correct-password"
    @browser.click_button "Sign in with password"
    expect(@browser).to have_text("Verification failed")
    expect(Session.count).to eq(0)
  end
end
