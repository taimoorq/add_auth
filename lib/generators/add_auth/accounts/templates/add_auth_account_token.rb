# frozen_string_literal: true

class AddAuthAccountToken < ApplicationRecord
  belongs_to :user
  self.filter_attributes += [:digest, :address_digest, :account_version, :delivery_payload, :delivery_lease_key]
end
