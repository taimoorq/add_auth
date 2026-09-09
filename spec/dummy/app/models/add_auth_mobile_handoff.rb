class AddAuthMobileHandoff < ApplicationRecord
  self.filter_attributes += [:external_digest, :digest, :state, :challenge_digest]
  belongs_to :user, optional: true
  def inspect = "#<AddAuthMobileHandoff [FILTERED]>"
end
