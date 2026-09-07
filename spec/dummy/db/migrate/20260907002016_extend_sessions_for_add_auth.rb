class ExtendSessionsForAddAuth < ActiveRecord::Migration[8.0]
  def change
    add_column :sessions, :token_digest, :string, limit: 64
    add_index :sessions, :token_digest, unique: true
    add_column :sessions, :authenticated_with, :string
    add_column :sessions, :authenticated_at, :datetime
    add_column :sessions, :expires_at, :datetime
    add_column :sessions, :last_seen_at, :datetime
    add_column :sessions, :revoked_at, :datetime
  end
end
