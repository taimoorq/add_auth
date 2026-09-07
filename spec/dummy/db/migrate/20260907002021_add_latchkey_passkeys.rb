class AddLatchkeyPasskeys < ActiveRecord::Migration[8.0]
  def change
    # Rails 8.0 cannot reflect SQLite's FALSE literal emitted by Rails 8.1.
    # Keep the additive schema readable by both supported Rails lines.
    false_default = (connection.adapter_name == "SQLite") ? -> { "0" } : false
    add_column :users, :webauthn_id, :string
    add_index :users, :webauthn_id, unique: true
    add_column :users, :latchkey_strict, :boolean, default: false_default, null: false
    add_column :users, :latchkey_policy_version, :integer, default: 0, null: false
    add_column :sessions, :authentication_policy_version, :integer, default: 0, null: false
    add_column :sessions, :authentication_credential_id, :string
    add_column :sessions, :authentication_uv, :boolean, default: false_default, null: false
    create_table :latchkey_credentials do |t|
      t.references :user, null: false, foreign_key: {on_delete: :cascade}
      t.string :external_id, null: false
      t.text :public_key, null: false
      t.bigint :sign_count, default: 0, null: false
      t.string :nickname, default: "Passkey", null: false, limit: 60
      t.string :aaguid
      t.json :transports
      t.boolean :backup_eligible, default: false_default, null: false
      t.boolean :backup_state, default: false_default, null: false
      t.datetime :last_used_at
      t.datetime :revoked_at
      t.timestamps
    end
    add_index :latchkey_credentials, :external_id, unique: true
    create_table :latchkey_ceremonies do |t|
      t.string :digest, null: false
      t.string :challenge, null: false
      t.string :kind, null: false
      t.string :browser_digest, null: false
      t.string :configuration_digest, null: false
      t.references :user, foreign_key: {on_delete: :cascade}
      t.references :session, foreign_key: {on_delete: :cascade}
      t.string :session_digest
      t.string :authentication_purpose
      t.datetime :expires_at, null: false
      t.datetime :consumed_at
      t.timestamps
    end
    add_index :latchkey_ceremonies, :digest, unique: true
    add_index :latchkey_ceremonies, :expires_at
  end
end
