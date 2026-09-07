# frozen_string_literal: true

require_relative "reauthentication"

RSpec.shared_context "passkey runtime" do
  include_context "public reauthentication"
  around do |example|
    config = Latchkey.configuration
    old = [config.passkeys.dup, config.notifications.enabled, config.trusted_recovery_address, config.support_url]
    config.passkeys.enabled = true
    config.passkeys.rp_id = "localhost"
    config.passkeys.origins = ["http://localhost"]
    config.notifications.enabled = true
    config.trusted_recovery_address = ->(user) { user.email_address }
    config.support_url = "/support"
    example.run
  ensure
    config.passkeys.members.each { |field| config.passkeys[field] = old[0][field] }
    config.notifications.enabled, config.trusted_recovery_address, config.support_url = old.drop(1)
  end
end
