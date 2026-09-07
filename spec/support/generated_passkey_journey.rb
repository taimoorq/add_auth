# frozen_string_literal: true

# Executed by Rails runner in the packaged, independently generated host.
require "webauthn/fake_client"
require "add_auth/testing"
default = User.connection.select_all("PRAGMA table_info(users)").find { |column| column["name"] == "add_auth_strict" }.fetch("dflt_value")
abort "cross-Rails boolean default lost" unless default == "0" && User.new.add_auth_strict == false
config = AddAuth.configuration
config.passkeys.rp_id = "example.test"
config.passkeys.origins = ["https://example.test"]
config.trusted_recovery_address = ->(user) { user.email_address }
config.support_url = "/support"
ActiveJob::Base.queue_adapter = :inline
ActionMailer::Base.delivery_method = :test
ActionMailer::Base.deliveries.clear
account = User.create!(email_address: "passkey-#{SecureRandom.hex(4)}@example.test", password: "correct-password")
client = ActionDispatch::Integration::Session.new(Rails.application)
client.host! "example.test"
client.post "/sign-in/password", params: {email_address: account.email_address, password: "correct-password"}
abort "password failed" unless client.response.status == 303
client.post "/reauthenticate/password", params: {purpose: :manage_passkeys, password: "correct-password"}
abort "enrollment proof failed" unless client.response.status == 303
client.post "/passkeys/options", as: :json
abort "options failed" unless client.response.status == 200
start = client.response.parsed_body
authenticator = WebAuthn::FakeClient.new("https://example.test", encoding: :base64url)
credential = authenticator.create(challenge: start.fetch("publicKey").fetch("challenge"), user_verified: true)
client.post "/passkeys", params: {transaction: start.fetch("transaction"), credential: credential, nickname: "Laptop"}, as: :json
abort "registration failed" unless client.response.status == 200
client.get "/passkeys"
abort "management page missing" unless client.response.body.include?("Laptop")
client.patch "/passkeys/#{AddAuthCredential.last.id}", params: {nickname: "Renamed laptop"}
abort "rename failed" unless client.response.status == 303
client.delete "/session"
client.post "/passkeys/sign-in/options", as: :json
start = client.response.parsed_body
credential = authenticator.get(challenge: start.fetch("publicKey").fetch("challenge"),
  user_verified: true, backup_state: false, user_handle: Base64.urlsafe_decode64(account.reload.webauthn_id))
client.post "/passkeys/sign-in", params: {transaction: start.fetch("transaction"), credential: credential}, as: :json
abort "passkey login failed" unless client.response.status == 200 && Session.last.authenticated_with == "passkey"
client.post "/reauthenticate/passkey/options", params: {purpose: :sign_out_everywhere}, as: :json
start = client.response.parsed_body
credential = authenticator.get(challenge: start.fetch("publicKey").fetch("challenge"),
  user_verified: true, backup_state: false, user_handle: Base64.urlsafe_decode64(account.webauthn_id))
client.post "/reauthenticate/passkey", params: {transaction: start.fetch("transaction"), credential: credential}, as: :json
abort "passkey elevation failed" unless client.response.status == 200
client.post "/sessions/revoke-all"
abort "passkey revoke-all failed" unless client.response.status == 303 && account.sessions.where(revoked_at: nil).none?
client.post "/recover/email", params: {email_address: account.email_address}
link = AddAuth::Testing.delivered_link(ActionMailer::Base.deliveries.last, purpose: :recovery)
client.get link.request_uri
abort "recovery confirmation missing" unless client.response.body.include?("Confirm passkey recovery")
client.post "/recover/link", params: {token: URI.decode_www_form(link.query).to_h.fetch("token"), switch_account: "1"}
abort "recovery grant failed" unless client.response.status == 303
client.post "/passkeys/options", as: :json
start = client.response.parsed_body
replacement = WebAuthn::FakeClient.new("https://example.test", encoding: :base64url)
credential = replacement.create(challenge: start.fetch("publicKey").fetch("challenge"), user_verified: true)
client.post "/passkeys", params: {transaction: start.fetch("transaction"), credential: credential}, as: :json
abort "replacement failed" unless client.response.status == 200 && AddAuthCredential.where(user: account).count == 2
abort "recovery notification missing" unless AddAuthSecurityEvent.where(user: account, kind: "recovery_completed").last&.delivered_at
%w[/add_auth/application.js /add_auth/codec.js /add_auth/passkey.js /add_auth/challenge.js].each do |path|
  client.get path
  abort "missing asset #{path}" unless client.response.status == 200
end
puts "packaged passkey recovery verified"
