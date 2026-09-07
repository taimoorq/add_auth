# frozen_string_literal: true

module AddAuth
  class SignInMailer < ActionMailer::Base
    module DeliveryReceipt
      def add_auth_delivery_completed? = @add_auth_delivery_completed == true
      def add_auth_delivery_completed! = @add_auth_delivery_completed = true
    end

    # Action Mailer's default instrumentation includes the entire bearer-bearing
    # message in debug logs. Keep this mailer's delivery event secret-free.
    def self.deliver_mail(mail)
      # Interceptors have already run. Suppression is cancellation, and errors
      # must propagate rather than silently turning a failed transport into success.
      return unless mail.perform_deliveries
      raise AddAuth::Error, "sign-in mail must report delivery errors" unless mail.raise_delivery_errors
      ActiveSupport::Notifications.instrument("deliver.add_auth", message_id: mail.message_id) { yield }
      mail.add_auth_delivery_completed!
    end

    self.raise_delivery_errors = true

    def link(recipient:, url:, purpose: "sign_in")
      from = Rails::Runtime.config.mail_from
      raise AddAuth::Error, "configure mail_from before delivering sign-in links" if from.to_s.empty?
      subject, instruction, minutes = {
        "sign_in" => ["Your sign-in link", "Open this link, then choose Sign in to confirm your account", Rails::Runtime.config.email_link.token_lifetime / 60],
        "reauthentication" => ["Verify your current session", "Open this link in the signed-in browser where you started, then confirm verification", 5],
        "recovery" => ["Recover your passkeys", "Open this link, then explicitly confirm that you want to recover your passkeys", 20]
      }.fetch(purpose.to_s)
      @url, @instruction, @minutes = url, instruction, minutes
      # No token-bearing mail body in Action Mailer's debug logs.
      mail(to: recipient, from: from, subject: subject, content_type: "text/plain").extend(DeliveryReceipt)
    end
  end
end
