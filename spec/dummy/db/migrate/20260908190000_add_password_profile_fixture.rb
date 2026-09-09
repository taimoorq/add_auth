# Test-only optional legacy-profile storage. Keep schema stable while examples
# run: rebuilding SQLite's users table between examples can rewrite defaults
# differently across Rails versions and contaminate unrelated stock-host tests.
class AddPasswordProfileFixture < ActiveRecord::Migration[8.0]
  def change
    add_column :users, :add_auth_password_scheme, :string
  end
end
