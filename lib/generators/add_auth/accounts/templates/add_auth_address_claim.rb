# frozen_string_literal: true

class AddAuthAddressClaim < ApplicationRecord
  belongs_to :user
  self.filter_attributes += [:digest]
end
