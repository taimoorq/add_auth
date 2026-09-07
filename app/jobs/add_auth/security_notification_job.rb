# frozen_string_literal: true

module AddAuth
  class SecurityNotificationJob < DeliveryJob
    def perform(id)
      record = ::AddAuthSecurityEvent.find_by(id: id)
      return unless record
      deliver(service: Rails::Runtime.security_events, record: record, mailer: SecurityMailer) do |delivery|
        SecurityMailer.notice(recipient: delivery.fetch(:recipient), kind: delivery.fetch(:kind))
      end
    end
  end
end
