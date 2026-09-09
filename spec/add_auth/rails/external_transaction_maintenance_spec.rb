# frozen_string_literal: true

require_relative "../../support/external_identity_host"
require "add_auth/rails/stores/maintenance"

RSpec.describe "External transaction retention", database: true do
  let(:now) { Time.current.change(usec: 0) }
  let(:store) { AddAuth::Rails::Stores::Maintenance.new(model: AddAuthExternalTransaction, kind: :external_transaction) }

  def transaction(**attributes)
    AddAuthExternalTransaction.create!(digest: SecureRandom.hex(32), browser_digest: SecureRandom.hex(32),
      provider_id: "example", issuer: "https://id.example.test", audience: "web",
      purpose: "enroll_external_identity", issued_at: now - 600, expires_at: now - 1,
      enrollment_payload: "encrypted-expiring-intake", **attributes)
  end

  it "removes expired intake in bounded resumable batches without requiring mail lease columns" do
    5.times { transaction }
    live = transaction(expires_at: now + 60)
    expect(store.purge_expired(before: now, now: now, limit: 2)).to eq(2)
    expect(store.purge_expired(before: now, now: now, limit: 2)).to eq(2)
    expect(store.purge_expired(before: now, now: now, limit: 2)).to eq(1)
    expect(store.purge_expired(before: now, now: now, limit: 2)).to eq(0)
    expect(AddAuthExternalTransaction.pluck(:id)).to eq([live.id])
    expect(live.reload.enrollment_payload).to eq("encrypted-expiring-intake")
  end

  it "rechecks the expiry predicate if a selected row changes before deletion" do
    row = transaction
    allow(store).to receive(:bounded).and_wrap_original do |method, *arguments|
      method.call(*arguments).tap { row.update!(expires_at: now + 60) }
    end
    expect(store.purge_expired(before: now, now: now, limit: 2)).to eq(0)
    expect(row.reload.enrollment_payload).to eq("encrypted-expiring-intake")
  end
end
