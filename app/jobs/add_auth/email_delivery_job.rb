# frozen_string_literal: true

module AddAuth
  class EmailDeliveryJob < DeliveryJob
    def perform(id)
      record = ::AddAuthSignInToken.find_by(id: id)
      return unless record
      service = Rails::Runtime.email(purpose: record.purpose)
      deliver(service: service, record: record, mailer: SignInMailer) do |delivery|
        SignInMailer.link(recipient: delivery.fetch(:recipient),
          url: Rails::Runtime.sign_in_url(delivery.fetch(:token), purpose: record.purpose), purpose: record.purpose)
      end
    end
  end
end
