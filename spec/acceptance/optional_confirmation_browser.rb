# frozen_string_literal: true

require_relative "../support/browser"

RSpec.describe "Optional signup in Chrome" do
  %i[turbo html no_js].each do |mode|
    it "registers, signs in, resets, changes email and deletes through #{mode} navigation" do
      config = AddAuth.configuration
      settings = config.lifecycle.to_h
      turbo = config.turbo_enabled
      adapter = ActiveJob::Base.queue_adapter
      csrf = ActionController::Base.allow_forgery_protection
      config.lifecycle.confirmation_required = false
      config.lifecycle.reset_unconfirmed = true
      config.turbo_enabled = mode == :turbo
      config.rate_limit_store.clear
      ActionController::Base.allow_forgery_protection = true
      ActiveJob::Base.queue_adapter = :inline
      ActionMailer::Base.deliveries.clear
      driver = (mode == :no_js) ? :add_auth_no_js : :add_auth_chrome
      browser = Capybara::Session.new(driver, Rails.application)
      email = "browser-#{mode}-#{SecureRandom.hex(5)}@example.test"
      browser.visit "/account/sign-up"
      expect(browser).to have_css("h1", text: "Create an account")
      expect(browser).to have_text("sign in right away")
      expect(browser).to have_css('meta[name="turbo-cache-control"][content="no-cache"]', visible: :all)
      AddAuthBrowserNavigation.wait_for_turbo(browser, enabled: mode == :turbo) unless mode == :no_js
      if ENV["ADD_AUTH_ACCEPTANCE_ARTIFACTS"]
        FileUtils.mkdir_p(ENV.fetch("ADD_AUTH_ACCEPTANCE_ARTIFACTS"))
        browser.save_screenshot(File.join(ENV.fetch("ADD_AUTH_ACCEPTANCE_ARTIFACTS"), "#{mode}-signup-#{Process.pid}.png"))
        browser.current_window.resize_to(390, 844)
        browser.save_screenshot(File.join(ENV.fetch("ADD_AUTH_ACCEPTANCE_ARTIFACTS"), "#{mode}-signup-narrow-#{Process.pid}.png"))
      end
      browser.fill_in "Email address", with: email
      browser.fill_in "New password", with: "short"
      browser.click_button "Create account"
      expect(browser).to have_css('[role="alert"]')
      expect(browser).to have_field("Email address", with: email)
      browser.fill_in "New password", with: "browser-account-password"
      browser.find('input[type="submit"]').send_keys(:enter)
      expect(browser).to have_css("h1", text: "Signed in")
      expect(browser).to have_current_path("/")
      account = User.find_by!(email_address: email)
      expect(account.confirmed_at).to be_nil
      expect(account.provision_count).to eq(1)
      expect(ActionMailer::Base.deliveries).to be_empty
      expect(Session.where(user_id: account.id).count).to eq(1)

      browser.visit "/account/sign-up"
      browser.fill_in "Email address", with: email
      browser.fill_in "New password", with: "another-account-password"
      browser.click_button "Create account"
      expect(browser).to have_css("h1", text: "Sign in")
      expect(Session.where(user_id: account.id).count).to eq(1)
      expect(account.reload.provision_count).to eq(1)
      expect(browser).not_to have_button("Send sign-in link")
      browser.fill_in "Email address", with: email
      browser.fill_in "Password", with: "browser-account-password"
      browser.click_button "Sign in with password"
      expect(browser).to have_css("h1", text: "Signed in")
      expect(account.reload.confirmed_at).to be_nil

      browser.current_window.resize_to(390, 844)
      browser.visit "/account/requests/reset_password"
      if mode != :no_js
        expect(browser.evaluate_script("document.documentElement.scrollWidth <= window.innerWidth")).to be(true)
      end
      browser.fill_in "Email address", with: email
      browser.click_button "Send account link"
      expect(browser).to have_css("h1", text: "Check your email")
      mail = ActionMailer::Base.deliveries.reverse.find { |message| message.to == [email] && message.subject == "Choose a new password" }
      expect(mail).to be_present
      browser.visit URI.parse(mail.body.decoded.scan(%r{https://[^[:space:]<>]+}).first).request_uri
      browser.fill_in "New password", with: "browser-reset-password"
      browser.click_button "Choose a new password"
      expect(browser).to have_current_path("/sign-in")
      expect(account.reload.confirmed_at).to be_nil
      expect(Session.where(user_id: account.id, revoked_at: nil)).to be_empty
      browser.fill_in "Email address", with: email
      browser.fill_in "Password", with: "browser-reset-password"
      browser.click_button "Sign in with password"
      expect(browser).to have_css("h1", text: "Signed in")

      browser.visit "/account/email"
      changed = "changed-#{email}"
      browser.fill_in "New email address", with: changed
      browser.click_button "Send confirmation link"
      expect(browser).to have_css("h1", text: "Verify it’s you")
      expect(browser).not_to have_button("Email me a verification link")
      browser.fill_in "Current password", with: "browser-reset-password"
      browser.click_button "Verify with password"
      expect(browser).to have_css("h1", text: "Change your email")
      browser.fill_in "New email address", with: changed
      browser.click_button "Send confirmation link"
      expect(browser).to have_css("h1", text: "Check your email")
      expect(account.reload.email_address).to eq(email)
      expect(account.confirmed_at).to be_nil
      mail = ActionMailer::Base.deliveries.reverse.find { |message| message.to == [changed] && message.subject == "Confirm your email address" }
      expect(mail).to be_present
      browser.visit URI.parse(mail.body.decoded.scan(%r{https://[^[:space:]<>]+}).first).request_uri
      expect(account.reload.email_address).to eq(email)
      browser.click_button "Confirm this email address"
      expect(browser).to have_current_path("/sign-in")
      expect(account.reload.email_address).to eq(changed)
      expect(account.confirmed_at).to be_present
      expect(account.provision_count).to eq(1)
      browser.fill_in "Email address", with: changed
      browser.fill_in "Password", with: "browser-reset-password"
      browser.click_button "Sign in with password"
      expect(browser).to have_css("h1", text: "Signed in")
      browser.visit "/account/delete"
      browser.click_button "Delete my account"
      expect(browser).to have_css("h1", text: "Verify it’s you")
      browser.fill_in "Current password", with: "browser-reset-password"
      browser.click_button "Verify with password"
      expect(browser).to have_css("h1", text: "Delete your account")
      expect(User.exists?(account.id)).to be(true)
      browser.click_button "Delete my account"
      expect(browser).to have_css("h1", text: "Sign in")
      expect(User.exists?(account.id)).to be(false)
      expect(Session.where(user_id: account.id)).to be_empty
    ensure
      browser&.quit
      settings&.each { |key, value| config.lifecycle.public_send("#{key}=", value) }
      config.turbo_enabled = turbo if config
      ActiveJob::Base.queue_adapter = adapter if adapter
      ActionController::Base.allow_forgery_protection = csrf
      Current.reset
    end
  end
end
