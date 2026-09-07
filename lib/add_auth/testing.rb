# frozen_string_literal: true

require "uri"

module AddAuth
  module Testing
    module_function

    def delivered_link(mail, purpose: :sign_in)
      path = {sign_in: "/sign-in/link", reauthentication: "/reauthenticate/link", recovery: "/recover/link"}.fetch(purpose)
      urls = mail.body.decoded.scan(%r{https?://[^\s<>]+}).filter_map do |text|
        uri = URI.parse(text)
        uri if uri.path == path && URI.decode_www_form(uri.query.to_s).to_h["token"]
      rescue URI::InvalidURIError, ArgumentError
        nil
      end
      raise ArgumentError, "expected exactly one #{purpose} link" unless urls.length == 1
      urls.first
    end

    def with_virtual_authenticator(driver, **options)
      require "selenium-webdriver"
      defaults = {protocol: :ctap2, transport: :internal, resident_key: true, user_verification: true, user_verified: true}
      authenticator = driver.add_virtual_authenticator(Selenium::WebDriver::VirtualAuthenticatorOptions.new(**defaults, **options))
      yield authenticator
    ensure
      authenticator.remove! if authenticator&.valid?
    end
  end
end
