# frozen_string_literal: true

require "net/smtp"

module AddAuth
  class DeliveryJob < ActiveJob::Base
    self.log_arguments = false
    retry_on StandardError, wait: :polynomially_longer, attempts: 8

    private

    def deliver(service:, record:, mailer:)
      delivery = service.claim_delivery(digest: record.digest)
      return unless delivery
      begin
        message = yield delivery
        raise AddAuth::Error, "mail delivery is disabled" unless mailer.perform_deliveries
        message.deliver_now
        outcome = message.add_auth_delivery_completed? ? :delivered : :cancelled
        if service.finish_delivery(digest: record.digest, lease: delivery.fetch(:lease), outcome: outcome) && outcome == :cancelled
          ActiveSupport::Notifications.instrument("delivery_cancelled.add_auth", issuance_id: record.id)
        end
      rescue Net::SMTPFatalError
        service.delivery_failed(digest: record.digest, lease: delivery.fetch(:lease))
      rescue
        service.delivery_retry(digest: record.digest, lease: delivery.fetch(:lease))
        raise
      end
    end
  end
end
