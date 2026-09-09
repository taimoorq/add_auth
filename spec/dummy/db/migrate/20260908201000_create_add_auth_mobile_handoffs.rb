class CreateAddAuthMobileHandoffs < ActiveRecord::Migration[8.0]
  def change
    user_key = connection.columns(:users).find { |column| column.name == connection.primary_key(:users) }
    raise "Unsupported authentication primary key" unless user_key && [:integer, :uuid].include?(user_key.type)
    user_type = (user_key.type == :integer && user_key.limit == 8) ? :bigint : user_key.type
    create_table :add_auth_mobile_handoffs do |t|
      t.references :user, type: user_type, foreign_key: {on_delete: :cascade}
      t.string :external_digest, null: false
      t.string :digest
      t.string :client_id, limit: 64, null: false
      t.string :callback, limit: 2048, null: false
      t.string :state, limit: 128, null: false
      t.string :challenge_digest, null: false
      t.string :credential_id
      t.string :credential_version
      t.integer :policy_version
      t.datetime :authenticated_at
      t.datetime :issued_at, null: false
      t.datetime :expires_at, null: false
      t.datetime :consumed_at
      t.timestamps
    end
    add_index :add_auth_mobile_handoffs, :external_digest, unique: true
    add_index :add_auth_mobile_handoffs, :digest, unique: true
    add_index :add_auth_mobile_handoffs, :expires_at
  end
end
