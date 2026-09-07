class LatchkeyCeremony < ApplicationRecord
  belongs_to :user, optional: true
  self.filter_attributes += [:digest, :challenge, :browser_digest, :session_digest, :public_key, :external_id]
end
