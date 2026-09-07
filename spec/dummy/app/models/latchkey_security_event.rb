class LatchkeySecurityEvent < ApplicationRecord
  belongs_to :user, optional: true
  self.filter_attributes += [:delivery_payload, :digest, :delivery_lease_key]
end
