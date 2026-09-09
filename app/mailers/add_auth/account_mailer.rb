# frozen_string_literal: true

module AddAuth
  class AccountMailer < SignInMailer
    def link(recipient:, url:, purpose:)
      @instruction = {"confirm" => "Confirm your email address", "reset_password" => "Choose a new password", "unlock" => "Unlock your account"}.fetch(purpose)
      @url = url
      mail(to: recipient, from: Rails::Runtime.config.mail_from, subject: @instruction,
        content_type: "text/plain").extend(SignInMailer::DeliveryReceipt)
    end
  end
end
