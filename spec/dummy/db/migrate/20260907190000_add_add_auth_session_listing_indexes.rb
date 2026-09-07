class AddAddAuthSessionListingIndexes < ActiveRecord::Migration[8.0]
  def change
    add_index :sessions, [:user_id, :id], name: "index_add_auth_session_pages"
    add_index :sessions, :expires_at
    add_index :sessions, :revoked_at
  end
end
