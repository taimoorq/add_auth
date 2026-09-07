# frozen_string_literal: true

require "rails_helper"
require_relative "../support/browser"

RSpec.describe "Session page navigation", database: true do
  %i[add_auth_chrome add_auth_no_js].each do |driver|
    it "navigates and revokes an older session with #{driver}" do
      user = User.create!(email_address: "pages@example.test", password: "correct-password")
      browser = Capybara::Session.new(driver, Rails.application)
      browser.visit "/sign-in"
      browser.fill_in "Email address", with: user.email_address
      browser.fill_in "Password", with: "correct-password"
      browser.click_button "Sign in with password"
      expect(browser).to have_text("Signed in")
      rows = 52.times.map do |i|
        AddAuth::Rails::Runtime.sessions.start(user: user, method: :password, user_agent: "Pagination browser #{i}").session
      end
      browser.visit "/sessions"
      expect(browser).to have_text("This browser")
      browser.click_link "Older sessions"
      expect(browser).to have_css("p", text: "Pagination browser 0", exact_text: true)
      expect(browser).not_to have_text("This browser")
      browser.within("#session_#{rows.first.id}") { browser.click_button "Revoke" }
      expect(browser).to have_text("This browser")
      expect(rows.first.reload.revoked_at).to be_present
      browser.click_link "Older sessions"
      expect(browser).not_to have_css("p", text: "Pagination browser 0", exact_text: true)
      browser.click_link "Newest sessions"
      expect(browser).to have_text("This browser")
    ensure
      browser&.quit
    end
  end
end
