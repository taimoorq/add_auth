# frozen_string_literal: true

require "capybara/rspec"
require "selenium-webdriver"

Capybara.server = :puma, {Silent: true}
Capybara.default_max_wait_time = 5
%i[add_auth_chrome add_auth_no_js].each do |name|
  Capybara.register_driver name do |app|
    options = Selenium::WebDriver::Chrome::Options.new
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1280,900")
    options.add_preference("profile.managed_default_content_settings.javascript", 2) if name == :add_auth_no_js
    options.add_option("goog:loggingPrefs", {browser: "ALL"})
    Capybara::Selenium::Driver.new(app, browser: :chrome, options: options)
  end
end

# Chrome 152 can report a detached document as UnknownError while Turbo swaps
# the body. Classify only this read failure as stale so Capybara reloads the
# element within its normal timeout. Never retry actions or other driver errors.
module AddAuthDetachedDocumentRead
  %i[visible_text visible?].each do |read|
    define_method(read) do
      super()
    rescue Selenium::WebDriver::Error::UnknownError => error
      raise unless error.message.include?("Node with given id does not belong to the document")
      raise Selenium::WebDriver::Error::StaleElementReferenceError, "document replaced during #{read}"
    end
  end
end
Capybara::Selenium::Node.prepend(AddAuthDetachedDocumentRead)
