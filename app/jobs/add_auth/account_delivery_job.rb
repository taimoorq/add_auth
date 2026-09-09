# frozen_string_literal: true

module AddAuth
  class AccountDeliveryJob < DeliveryJob
    def perform(id)
      record = ::AddAuthAccountToken.find_by(id: id)
      return unless record
      deliver(service: Rails::Runtime.accounts, record: record, mailer: AccountMailer) do |delivery|
        AccountMailer.link(recipient: delivery.fetch(:recipient), purpose: delivery.fetch(:purpose),
          url: Rails::Runtime.account_proof_url(delivery.fetch(:token), purpose: delivery.fetch(:purpose)))
      end
    end
  end
end
