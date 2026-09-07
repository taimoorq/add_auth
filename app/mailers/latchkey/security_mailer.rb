# frozen_string_literal: true

module Latchkey
  class SecurityMailer < SignInMailer
    def notice(recipient:, kind:)
      @description = {
        "password_changed" => "Your password changed.", "email_changed" => "Your account email address changed.",
        "passkey_added" => "A passkey was added to your account.", "passkey_removed" => "A passkey was removed from your account.",
        "policy_changed" => "Your account sign-in and recovery policy changed.", "recovery_completed" => "Passkey recovery completed on your account."
      }.fetch(kind.to_s)
      from = Rails::Runtime.config.mail_from
      raise Latchkey::Error, "configure mail_from before delivering security notifications" if from.to_s.empty?
      mail(to: recipient, from: from, subject: "Account security change", content_type: "text/plain").extend(DeliveryReceipt)
    end
  end
end
