# frozen_string_literal: true

RSpec.shared_context "public reauthentication" do
  around do |example|
    options = Latchkey.configuration.step_up
    old = [options.enabled, options.purposes]
    options.enabled = true
    options.purposes = {
      manage_profile: {methods: [:password, :email_link], return_to: "/sensitive", label: "update your profile"},
      export: {methods: [:password, :email_link], return_to: "/", label: "export your account"},
      strong: {methods: [:passkey], require_passkey: true, return_to: "/"}
    }
    example.run
  ensure
    options.enabled, options.purposes = old
  end
end
