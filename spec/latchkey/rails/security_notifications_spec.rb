# frozen_string_literal: true

require "rails_helper"
require "rake"

RSpec.describe "Durable security notifications", database: true do
  include ActiveJob::TestHelper

  let!(:user) { User.create!(email_address: "notice@example.test", password: "correct-password") }
  let(:service) { Latchkey::Rails::Runtime.security_events }

  around do |example|
    previous = Latchkey.configuration.notifications.enabled
    Latchkey.configuration.notifications.enabled = true
    example.run
  ensure
    Latchkey.configuration.notifications.enabled = previous
  end

  def issue
    User.transaction { service.issue(user: user, kind: :passkey_added, at: Time.current) }
  end

  it "commits a protected intent then delivers only a security notice" do
    record = issue
    expect(record.attributes.inspect).not_to include(user.email_address)
    expect(enqueued_jobs.inspect).not_to include(user.email_address)
    perform_enqueued_jobs
    expect(record.reload.delivered_at).to be_present
    expect(record.delivery_payload).to be_nil
    mail = ActionMailer::Base.deliveries.last
    expect(mail.to).to eq([user.email_address])
    expect(mail.body.decoded).to include("A passkey was added")
    expect(mail.body.decoded).not_to include("http", "lk1:")
  end

  it "does not send or keep an intent from a rolled-back mutation" do
    User.transaction do
      service.issue(user: user, kind: :passkey_removed, at: Time.current)
      raise ActiveRecord::Rollback
    end
    expect(LatchkeySecurityEvent.count).to eq(0)
    expect(enqueued_jobs).to be_empty
    expect(ActionMailer::Base.deliveries).to be_empty
  end

  it "keeps a committed intent when enqueue fails and recovers it in the shared sweep" do
    allow(Latchkey::SecurityNotificationJob).to receive(:perform_later).and_return(false)
    record = issue
    expect(record.reload.delivery_payload).to be_present
    allow(Latchkey::SecurityNotificationJob).to receive(:perform_later).and_call_original
    Rails.application.load_tasks unless Rake::Task.task_defined?("latchkey:deliver_pending")
    Rake::Task["latchkey:deliver_pending"].reenable
    perform_enqueued_jobs { Rake::Task["latchkey:deliver_pending"].invoke }
    expect(record.reload.delivered_at).to be_present
  end

  it "grants only one concurrent delivery lease and rejects a stale worker receipt" do
    record = issue
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection { service.claim_delivery(digest: record.digest) }
      end
    end
    claims = threads.map(&:value).compact
    expect(claims.length).to eq(1)
    expect(service.delivery_succeeded(digest: record.digest, lease: "stale")).to be(false)
    expect(record.reload.delivered_at).to be_nil
    expect(service.delivery_succeeded(digest: record.digest, lease: claims.first.fetch(:lease))).to be(true)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "erases expired payloads and removes expired ceremonies without removing live proofs" do
    record = issue
    record.update!(expires_at: Time.current)
    attributes = {challenge: "challenge", kind: "assertion", browser_digest: "binding", configuration_digest: "config"}
    expired = LatchkeyCeremony.create!(**attributes, digest: "expired", expires_at: Time.current)
    live = LatchkeyCeremony.create!(**attributes, digest: "live", expires_at: 5.minutes.from_now)
    Rails.application.load_tasks unless Rake::Task.task_defined?("latchkey:deliver_pending")
    Rake::Task["latchkey:deliver_pending"].reenable
    Rake::Task["latchkey:deliver_pending"].invoke
    expect(record.reload.delivery_payload).to be_nil
    expect(LatchkeyCeremony.exists?(expired.id)).to be(false)
    expect(LatchkeyCeremony.exists?(live.id)).to be(true)
  end

  it "retries an ambiguous transport error with the same event and suppresses cancelled notices" do
    record = issue
    allow(Latchkey::SecurityMailer).to receive(:notice).and_raise(IOError, "ambiguous send")
    Latchkey::SecurityNotificationJob.perform_now(record.id)
    expect(record.reload.delivery_lease_key).to be_nil
    expect(record.delivery_payload).to be_present
    allow(Latchkey::SecurityMailer).to receive(:notice).and_call_original
    callback = -> { throw :abort }
    Latchkey::SecurityMailer.before_deliver(callback)
    Latchkey::SecurityNotificationJob.perform_now(record.id)
    expect(record.reload.revoked_at).to be_present
    expect(record.delivered_at).to be_nil
    expect(record.delivery_payload).to be_nil
  ensure
    Latchkey::SecurityMailer.skip_callback(:deliver, :before, callback) if callback
  end

  it "notifies the previous address after an address change and the current address after a reset" do
    perform_enqueued_jobs { user.update!(email_address: "replacement@example.test") }
    expect(ActionMailer::Base.deliveries.map(&:to)).to contain_exactly(["notice@example.test"], ["replacement@example.test"])
    ActionMailer::Base.deliveries.clear
    perform_enqueued_jobs { user.update!(password: "new-password") }
    expect(ActionMailer::Base.deliveries.last.to).to eq(["replacement@example.test"])
    expect(ActionMailer::Base.deliveries.last.body.decoded).to include("Your password changed")
  end
end
