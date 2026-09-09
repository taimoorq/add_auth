class AddAddAuthMobileSessions < ActiveRecord::Migration[8.0]
  def change
    add_column :sessions, :transport, :string, null: false, default: "browser"
    add_column :sessions, :client_id, :string
    add_column :sessions, :mobile_idle_timeout, :integer
    add_check_constraint :sessions, "transport IN ('browser', 'mobile')", name: "add_auth_session_transport"
    add_check_constraint :sessions, "transport != 'mobile' OR (client_id IS NOT NULL AND mobile_idle_timeout IS NOT NULL AND mobile_idle_timeout BETWEEN 60 AND 7776000 AND token_digest IS NOT NULL AND authenticated_at IS NOT NULL AND expires_at IS NOT NULL AND last_seen_at IS NOT NULL)", name: "add_auth_mobile_profile"
  end
end
