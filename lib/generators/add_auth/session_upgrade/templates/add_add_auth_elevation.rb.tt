class AddAddAuthElevation < ActiveRecord::Migration[8.0]
  def change
    # Rails 8.0 cannot reflect SQLite's FALSE literal emitted by Rails 8.1.
    # Keep the additive schema readable by both supported Rails lines.
    false_default = (connection.adapter_name == "SQLite") ? -> { "0" } : false
    add_column :sessions, :elevated_at, :datetime
    add_column :sessions, :elevated_with, :string
    add_column :sessions, :elevation_purpose, :string
    add_column :sessions, :elevation_credential_id, :string
    add_column :sessions, :elevation_uv, :boolean, default: false_default, null: false
  end
end
