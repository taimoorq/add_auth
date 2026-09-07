# frozen_string_literal: true

require "rails_helper"
require_relative "../support/browser"
require_relative "../support/reauthentication"

RSpec.describe "Reauthentication browser journeys", database: true do
  include_context "public reauthentication"
  let!(:user) { User.create!(email_address: "reauth@example.test", password: "correct-password") }

  around do |example|
    old_csrf = ActionController::Base.allow_forgery_protection
    adapter = ActiveJob::Base.queue_adapter
    ActionController::Base.allow_forgery_protection = true
    example.run
  ensure
    ActionController::Base.allow_forgery_protection = old_csrf
    ActiveJob::Base.queue_adapter = adapter
  end

  before { ActiveJob::Base.queue_adapter = :inline }

  %i[latchkey_chrome latchkey_no_js].each do |driver|
    %i[password email_link].each do |method|
      it "verifies with #{method} in #{driver} then waits for a separate confirmation" do
        browser = Capybara::Session.new(driver, Rails.application)
        browser.visit "/sign-in"
        browser.fill_in "Email address", with: user.email_address
        browser.fill_in "Password", with: "correct-password"
        browser.click_button "Sign in with password"
        expect(browser).to have_text("Signed in")
        browser.visit "/sensitive"
        browser.click_button "Confirm profile change"
        expect(browser).to have_text("Verify it’s you")
        if method == :password
          browser.fill_in "Current password", with: "wrong-password"
          browser.click_button "Verify with password"
          expect(browser).to have_css('[role="alert"]')
          browser.fill_in "Current password", with: "correct-password"
          browser.click_button "Verify with password"
        else
          browser.click_button "Email me a verification link"
          expect(browser).to have_text("Check your email")
          link = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\s]+/])
          outsider = Capybara::Session.new(driver, Rails.application)
          outsider.visit link.request_uri
          expect(outsider).to have_text("Return to the browser where you started")
          expect(outsider).not_to have_button("Confirm verification")
          browser.visit link.request_uri
          browser.click_button "Confirm verification"
        end
        expect(browser).to have_text("Review profile change")
        expect(browser).not_to have_text("Profile change completed")
        expect(Session.count).to eq(1)
        browser.click_button "Confirm profile change"
        expect(browser).to have_text("Profile change completed")
      ensure
        browser&.quit
        outsider&.quit
      end
    end
  end
end
