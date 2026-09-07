class User < ApplicationRecord
  has_many :add_auth_sign_in_tokens, dependent: :delete_all
  include AddAuth::Rails::UserLifecycle

  has_secure_password
  has_many :sessions, dependent: :destroy

  normalizes :email_address, with: ->(e) { e.strip.downcase }
end
