class AddAuthExternalIdentity < ApplicationRecord
  belongs_to :user
  def inspect = "#<AddAuthExternalIdentity [FILTERED]>"
end
