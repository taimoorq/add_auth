# frozen_string_literal: true

require_relative "../../support/external_identity_host"
require "add_auth/rails/provider_enrollment"

RSpec.describe AddAuth::Rails::ProviderEnrollment, database: true do
  include ActiveSupport::Testing::TimeHelpers

  let(:digest) { AddAuth.configuration.sign_in_token_digest }
  let(:browser) { AddAuth::Core::BrowserBinding.new(digest: digest).generate }
  let(:configuration) { AddAuth::Core::ExternalIdentities::Configuration.new(id: "example", issuer: "https://id.example.test", audience: "web", verifier: ->(**_) {}) }
  let(:service) do
    AddAuth::Core::ExternalIdentities.new(store: AddAuth::Rails::Stores::ExternalIdentities.new(user_model: User,
      identity_model: AddAuthExternalIdentity, transaction_model: AddAuthExternalTransaction), configurations: [configuration],
      sessions: nil, access_policy: nil, policy: nil, eligible: ->(_) { true }, digest: digest,
      revoke_authority: ->(**_) {}, remaining_method: ->(_) { false }, enabled: true)
  end
  let(:pending) { service.begin_transaction(configuration_id: configuration.id, browser_secret: browser, purpose: :enroll_external_identity).credential }
  subject(:intake) { described_class.new(model: AddAuthExternalTransaction, digest: digest, key: "fixture-enrollment-key".ljust(32, ".")) }
  let(:profile) { {name: "New reader", consent: "1"} }

  it "keeps bounded profile data encrypted on its exact expiring transaction and erases it" do
    expect(intake.write(pending: pending, identifier: "reader@example.test", profile: profile)).to be(true)
    row = AddAuthExternalTransaction.find_by!(digest: digest.digest(pending.id))
    expect(row.enrollment_payload).not_to include("New reader", "reader@example.test")
    expect(intake.read(pending: pending)).to eq(identifier: "reader@example.test", profile: profile)
    expect(intake.write(pending: pending, identifier: "changed@example.test", profile: {})).to be(false)
    other = service.begin_transaction(configuration_id: configuration.id, browser_secret: browser, purpose: :enroll_external_identity).credential
    AddAuthExternalTransaction.find_by!(digest: digest.digest(other.id)).update!(enrollment_payload: row.enrollment_payload)
    expect(intake.read(pending: other)).to be_nil
    intake.erase(pending: pending)
    expect(row.reload.enrollment_payload).to be_nil
    expect(intake.read(pending: pending)).to be_nil
    expect(User.count).to eq(0)
    expect(Session.count).to eq(0)
  end

  it "rejects malformed and excessive data without writing a payload" do
    expect(intake.write(pending: pending, identifier: "reader@example.test", profile: {name: {role: "admin"}})).to be(false)
    expect(intake.write(pending: pending, identifier: "reader@example.test", profile: {name: "a" * 2049})).to be(false)
    expect(intake.write(pending: pending, identifier: "reader@example.test", profile: {name: "a" * 2048, bio: "b" * 2048})).to be(false)
    expect(intake.write(pending: pending, identifier: "\xff".dup.force_encoding("UTF-8"), profile: {})).to be(false)
    ordinary = service.begin_transaction(configuration_id: configuration.id, browser_secret: browser).credential
    expect(intake.write(pending: ordinary, identifier: "reader@example.test", profile: {})).to be(false)
    expect(AddAuthExternalTransaction.where.not(enrollment_payload: nil)).to be_empty
  end

  it "does not recover modified or expired intake" do
    expect(intake.write(pending: pending, identifier: "reader@example.test", profile: profile)).to be(true)
    travel_to(pending.expires_at + 1) { expect(intake.read(pending: pending)).to be_nil }
    row = AddAuthExternalTransaction.find_by!(digest: digest.digest(pending.id))
    row.update!(enrollment_payload: "invalid")
    expect(intake.read(pending: pending)).to be_nil
  end
end
