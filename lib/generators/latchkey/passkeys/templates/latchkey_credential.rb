class LatchkeyCredential < ApplicationRecord
  belongs_to :user
  self.filter_attributes += [:digest, :challenge, :browser_digest, :session_digest, :public_key, :external_id]
end
