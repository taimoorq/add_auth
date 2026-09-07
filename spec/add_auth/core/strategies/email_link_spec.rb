# frozen_string_literal: true

require_relative "../../../support/memory_email_tokens"
require_relative "../../../support/email_token_contract"

RSpec.describe AddAuth::Core::Strategies::EmailLink do
  let(:store) { EmailTokenSupport::Store.new }
  let(:cipher) { EmailTokenSupport::Cipher.new }
  let(:user) { store.user }

  def rows = store.tokens
  def sessions = store.sessions

  def persist_session(account)
    session = EmailTokenSupport::Session.new(account.id)
    store.sessions << session
    session
  end

  def disable_user = user.email_address = "disabled@example.test"
  def change_purpose(record) = record.purpose = "recovery"

  include_examples "email token lifecycle"
  include_examples "address-bound email proof"

  def change_address = user.email_address = "changed@example.test"

  it "rejects invalid token lifetime configuration" do
    [0, -1, Float::INFINITY, Float::NAN, "20"].each do |lifetime|
      expect {
        described_class.new(store: store, digest: digest, delivery_cipher: cipher,
          eligible: ->(_) { true }, normalize_identifier: ->(value) { value }, identifier_for: ->(account) { account.email_address }, token_lifetime: lifetime)
      }.to raise_error(ArgumentError)
    end
  end
end
