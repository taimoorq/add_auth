class AddLatchkeyReauthentication < ActiveRecord::Migration[8.0]
  def change
    add_column :sessions, :elevation_version, :string
    add_column :sessions, :elevation_expires_at, :datetime
    add_reference :latchkey_sign_in_tokens, :session, foreign_key: {on_delete: :cascade}
    add_column :latchkey_sign_in_tokens, :session_digest, :string
    add_column :latchkey_sign_in_tokens, :authentication_purpose, :string
  end
end
