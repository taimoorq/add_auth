class AddAuthExternalTransaction < ApplicationRecord
  self.filter_attributes += [:enrollment_payload, :digest, :browser_digest, :session_digest]
  belongs_to :user, optional: true
  belongs_to :session, optional: true
  def inspect = "#<AddAuthExternalTransaction [FILTERED]>"
end
