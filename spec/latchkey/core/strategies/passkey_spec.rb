# frozen_string_literal: true

require_relative "../../../support/memory_passkeys"
require_relative "../../../support/passkey_contract"

RSpec.describe Latchkey::Core::Strategies::Passkey do
  let(:store) { PasskeyStoreSupport::Store.new }
  let(:session_store) { store }
  let(:user) { store.user }
  include_examples "passkey store contract"
end

RSpec.describe "Passkey configuration errors" do
  let(:options) do
    {store: nil, sessions: nil, policy: nil, access_policy: nil, digest: nil, eligible: nil,
     rp_id: "example.test", origins: ["https://example.test"], name: "Test", notify: nil, limiter: nil}
  end

  it "reports missing, malformed and unsafe host settings as service errors" do
    [{rp_id: nil}, {rp_id: "com"}, {origins: []}, {origins: [nil]}, {origins: ["http://example.test"]},
      {origins: ["https://unrelated.test"]}, {origins: ["https://example.test/path"]},
      {support_url: "https://unrelated.test"}, {anonymous_limit: nil}, {anonymous_limit: 0}, {anonymous_limit: 1.5}].each do |invalid|
      expect { Latchkey::Core::Strategies::Passkey.new(**options.merge(invalid)) }.to raise_error(Latchkey::Error)
    end
  end
end
