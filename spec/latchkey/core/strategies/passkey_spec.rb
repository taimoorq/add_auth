# frozen_string_literal: true

require_relative "../../../support/memory_passkeys"
require_relative "../../../support/passkey_contract"

RSpec.describe Latchkey::Core::Strategies::Passkey do
  let(:store) { PasskeyStoreSupport::Store.new }
  let(:session_store) { store }
  let(:user) { store.user }
  include_examples "passkey store contract"
end
