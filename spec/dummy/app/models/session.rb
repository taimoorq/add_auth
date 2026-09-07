class Session < ApplicationRecord
  self.filter_attributes += [:token_digest, :elevation_credential_id]
  belongs_to :user
end
