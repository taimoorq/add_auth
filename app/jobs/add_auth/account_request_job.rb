# frozen_string_literal: true

module AddAuth
  class AccountRequestJob < ActiveJob::Base
    self.log_arguments = false
    retry_on StandardError, wait: :polynomially_longer, attempts: 8

    def perform(encrypted_identifier)
      payload = Rails::Runtime.decrypt_intake(encrypted_identifier)
      if payload.is_a?(Hash)
        Rails::Runtime.accounts.issue(identifier: payload["identifier"], purpose: payload["purpose"], request_id: job_id)
      end
      record = ::AddAuthAccountToken.find_by(request_id: job_id)
      AccountDeliveryJob.perform_later(record.id) if record
    end
  end
end
