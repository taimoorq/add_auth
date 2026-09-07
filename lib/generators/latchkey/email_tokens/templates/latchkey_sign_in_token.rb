class LatchkeySignInToken < ApplicationRecord
  belongs_to :user
  self.filter_attributes += [:delivery_payload, :digest]
end
