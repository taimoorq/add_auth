# frozen_string_literal: true

module AddAuth
  class EmailRequestJob < ActiveJob::Base
    self.log_arguments = false
    retry_on StandardError, wait: :polynomially_longer, attempts: 8

    def perform(encrypted_identifier)
      payload = Rails::Runtime.decrypt_intake(encrypted_identifier)
      # Continue accepting encrypted identifier-only jobs from the prior deploy.
      identifier = payload.is_a?(Hash) ? payload["identifier"] : payload
      browser_digest = payload["browser_digest"] if payload.is_a?(Hash)
      # Dispatch an already committed intent even after the intake has expired.
      purpose = payload.is_a?(Hash) ? payload.fetch("purpose", "sign_in") : "sign_in"
      context = payload.is_a?(Hash) ? payload.slice("session_id", "session_digest", "authentication_purpose").symbolize_keys : {}
      Rails::Runtime.email(purpose: purpose).issue(identifier: identifier, request_id: job_id, browser_digest: browser_digest, **context) if identifier
      record = ::AddAuthSignInToken.find_by(request_id: job_id)
      EmailDeliveryJob.perform_later(record.id) if record
    end
  end
end
