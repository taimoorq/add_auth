class AddAddAuthEmailDelivery < ActiveRecord::Migration[8.0]
  def change
    add_column :add_auth_sign_in_tokens, :request_id, :string
    add_index :add_auth_sign_in_tokens, :request_id, unique: true
    add_column :add_auth_sign_in_tokens, :delivery_lease_key, :string
    add_column :add_auth_sign_in_tokens, :delivery_lease_until, :datetime
    add_column :add_auth_sign_in_tokens, :delivered_at, :datetime
    add_index :add_auth_sign_in_tokens, [:delivered_at, :expires_at], name: "index_add_auth_pending_delivery"
  end
end
