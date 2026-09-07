class CreateAddAuthSecurityEvents < ActiveRecord::Migration[8.0]
  def change
    create_table :add_auth_security_events do |t|
      t.references :user, foreign_key: {on_delete: :nullify}
      t.string :kind, null: false
      t.string :digest, null: false
      t.text :delivery_payload
      t.string :delivery_lease_key
      t.datetime :delivery_lease_until
      t.datetime :delivered_at
      t.datetime :revoked_at
      t.datetime :expires_at, null: false
      t.timestamps
    end
    add_index :add_auth_security_events, :digest, unique: true
    add_index :add_auth_security_events, :expires_at
  end
end
