# frozen_string_literal: true

require "rails_helper"
require "add_auth/rails/stores/maintenance"

RSpec.describe AddAuth::Rails::Stores::Maintenance, database: true do
  let!(:user) { User.create!(email_address: "retention@example.test", password: "correct-password") }
  let(:now) { Time.current.change(usec: 0) }
  let(:store) { described_class.new(model: Session, kind: :session) }

  def session(**attributes)
    user.sessions.create!(expires_at: now + 60, last_seen_at: now, **attributes)
  end

  it "bounds each deletion, preserves live authority and resumes after a partial pass" do
    old = 5.times.map { session(expires_at: now - 120) }
    live = session
    recent = session(expires_at: now - 30)
    legacy = user.sessions.create!
    revoked = session(revoked_at: now - 120)
    3.times { expect(store.purge_expired(before: now - 60, now: now, limit: 2)).to eq(2) }
    expect(store.purge_expired(before: now - 60, now: now, limit: 2)).to eq(0)
    expect(Session.pluck(:id)).to contain_exactly(live.id, recent.id, legacy.id)
    expect(Session.where(id: old.map(&:id) + [revoked.id])).not_to exist
  end

  it "rechecks expiry after selection so a concurrent refresh survives" do
    row = session(expires_at: now - 120)
    allow(store).to receive(:bounded).and_wrap_original do |method, *args|
      method.call(*args).tap { row.update!(expires_at: now + 120) }
    end
    expect(store.purge_expired(before: now, now: now, limit: 2)).to eq(0)
    expect(row.reload.expires_at).to eq(now + 120)
  end

  it "protects an active delivery lease from secret erasure and receipt retention" do
    attributes = {kind: "password_changed", delivery_payload: "encrypted", expires_at: now - 120}
    active = AddAuthSecurityEvent.create!(**attributes, digest: "leased", delivery_lease_until: now + 60)
    expired = AddAuthSecurityEvent.create!(**attributes, digest: "expired", delivery_lease_until: now)
    receipts = described_class.new(model: AddAuthSecurityEvent, kind: :notification)
    expect(receipts.erase_expired_payloads(now: now, limit: 1)).to eq(1)
    expect(expired.reload.delivery_payload).to be_nil
    expect(active.reload.delivery_payload).to eq("encrypted")
    expect(receipts.purge_expired(before: now, now: now, limit: 1)).to eq(1)
    expect(AddAuthSecurityEvent.pluck(:id)).to eq([active.id])
  end

  it "bounds dispatch and excludes delivered, revoked, expired and leased rows" do
    attributes = {kind: "password_changed", delivery_payload: "encrypted", expires_at: now + 120}
    eligible = 3.times.map { |i| AddAuthSecurityEvent.create!(**attributes, digest: "ready-#{i}") }
    [{delivered_at: now}, {revoked_at: now}, {expires_at: now}, {delivery_lease_until: now + 60}, {delivery_payload: nil}].each_with_index do |excluded, i|
      AddAuthSecurityEvent.create!(**attributes, **excluded, digest: "skip-#{i}")
    end
    receipts = described_class.new(model: AddAuthSecurityEvent, kind: :notification)
    expect(receipts.pending_ids(now: now, limit: 2)).to eq(eligible.first(2).map(&:id))
    eligible.first.update!(delivered_at: now, delivery_payload: nil)
    expect(receipts.pending_ids(now: now, limit: 2)).to eq(eligible.last(2).map(&:id))
  end

  it "allows overlapping sweeps to converge without double-counting deleted history" do
    5.times { session(expires_at: now - 120) }
    ready, go = Queue.new, Queue.new
    workers = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          described_class.new(model: Session, kind: :session).purge_expired(before: now, now: now, limit: 5)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    expect(workers.map(&:value).sum).to eq(5)
    expect(Session.count).to eq(0)
  ensure
    workers&.each { |thread| thread.kill if thread.alive? }
  end
end
