class AddLatchkeyEmailBinding < ActiveRecord::Migration[8.0]
  def change
    add_column :latchkey_sign_in_tokens, :browser_digest, :string
  end
end
