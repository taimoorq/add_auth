# frozen_string_literal: true

require "rails_helper"
require "rake"

RSpec.describe "Mail worker", database: true do
  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }
  let(:service) { AddAuth::Rails::Runtime.email }

  def issue
    service.issue(identifier: user.email_address)
    AddAuthSignInToken.last
  end

  it "reuses the committed issuance across request-job retries, including after delivery" do
    job = AddAuth::EmailRequestJob.new
    payload = AddAuth::Rails::Runtime.encrypt_intake(user.email_address)
    2.times { job.perform(payload) }
    expect(AddAuthSignInToken.count).to eq(1)
    row = AddAuthSignInToken.last
    raw = service.delivery_token(digest: row.digest)
    AddAuth::EmailDeliveryJob.new.perform(row.id)
    job.perform(payload)
    expect(AddAuthSignInToken.count).to eq(1)
    expect(row.reload.revoked_at).to be_nil
    expect(ActionMailer::Base.deliveries.last.body.decoded).to include(raw)
  end

  it "claims a delivery once and permits abandoned leases to recover with the same token" do
    row = issue
    first = service.claim_delivery(digest: row.digest)
    expect(service.claim_delivery(digest: row.digest)).to be_nil
    row.update!(delivery_lease_until: 1.second.ago)
    second = service.claim_delivery(digest: row.digest)
    expect(second.fetch(:token)).to eq(first.fetch(:token))
    expect(second.fetch(:lease)).not_to eq(first.fetch(:lease))
    service.delivery_succeeded(digest: row.digest, lease: first.fetch(:lease))
    expect(row.reload.delivered_at).to be_nil
    service.delivery_succeeded(digest: row.digest, lease: second.fetch(:lease))
    expect(row.reload.delivery_payload).to be_nil
  end

  it "retries ambiguous failure with the same bearer and never holds a DB lock over delivery" do
    row = issue
    raw = service.delivery_token(digest: row.digest)
    attempts = 0
    allow(AddAuth::SignInMailer).to receive(:link).and_wrap_original do |original, **arguments|
      expect(ActiveRecord::Base.connection.transaction_open?).to be(false)
      expect(arguments.fetch(:url)).to include(raw)
      attempts += 1
      raise IOError, "transport interrupted" if attempts == 1
      original.call(**arguments)
    end
    worker = AddAuth::EmailDeliveryJob.new
    expect { worker.perform(row.id) }.to raise_error(IOError)
    expect(row.reload.revoked_at).to be_nil
    expect(row.delivery_lease_until).to be_nil
    worker.perform(row.id)
    expect(attempts).to eq(2)
    expect(row.reload.delivered_at).to be_present
  end

  it "revokes only a permanently failed issuance while preserving a newer resend" do
    old = issue
    newer = nil
    allow(AddAuth::SignInMailer).to receive(:link) do
      newer = issue
      raise Net::SMTPFatalError, "550 recipient rejected"
    end
    AddAuth::EmailDeliveryJob.new.perform(old.id)
    expect(old.reload.revoked_at).to be_present
    expect(newer.reload.revoked_at).to be_nil
    expect(service.delivery_token(digest: newer.digest)).to be_present
  end

  it "skips revoked, consumed, expired and no-longer-eligible intents" do
    old = issue
    current = issue
    AddAuth::EmailDeliveryJob.new.perform(old.id)
    current.update!(expires_at: 1.second.ago)
    AddAuth::EmailDeliveryJob.new.perform(current.id)
    current = issue
    current.update!(consumed_at: Time.current)
    AddAuth::EmailDeliveryJob.new.perform(current.id)
    current = issue
    original = AddAuth.configuration.eligible
    AddAuth.configuration.eligible = ->(_) { false }
    AddAuth::EmailDeliveryJob.new.perform(current.id)
    expect(ActionMailer::Base.deliveries).to be_empty
  ensure
    AddAuth.configuration.eligible = original
  end

  it "does not leak tokens into Action Mailer debug logs" do
    row = issue
    raw = service.delivery_token(digest: row.digest)
    output = StringIO.new
    old_logger = ActionMailer::Base.logger
    ActionMailer::Base.logger = ActiveSupport::Logger.new(output)
    AddAuth::EmailDeliveryJob.new.perform(row.id)
    expect(output.string).not_to include(raw, user.email_address)
    expect(ActionMailer::Base.deliveries.last.body.decoded).to include(raw)
  ensure
    ActionMailer::Base.logger = old_logger
  end

  it "rejects attacker-controlled or insecure production link origins" do
    config = AddAuth.configuration
    old = config.base_url
    ["https://user@evil.test", "https://example.test/path", "https://example.test?next=evil"].each do |value|
      config.base_url = value
      expect { AddAuth::Rails::Runtime.sign_in_url("token") }.to raise_error(AddAuth::Error)
    end
  ensure
    config.base_url = old
  end
  it "recovers pending leases and scrubs expired ciphertext through the sweep task" do
    Rails.application.load_tasks unless Rake::Task.task_defined?("add_auth:deliver_pending")
    expired = issue
    expired.update!(expires_at: 1.second.ago)
    pending = issue
    pending.update!(delivery_lease_until: 1.second.ago)
    task = Rake::Task["add_auth:deliver_pending"]
    task.reenable
    task.invoke
    expect(expired.reload.delivery_payload).to be_nil
    jobs = ActiveJob::Base.queue_adapter.enqueued_jobs
    expect(jobs.map { |job| job.fetch(:args) }).to eq([[pending.id]])
  end

  it "does not mark mail delivered when the host disables delivery" do
    row = issue
    allow(AddAuth::SignInMailer).to receive(:perform_deliveries).and_return(false)
    expect { AddAuth::EmailDeliveryJob.new.perform(row.id) }.to raise_error(AddAuth::Error, /disabled/)
    expect(row.reload.delivered_at).to be_nil
    expect(row.delivery_payload).to be_present
  end

  %i[abort suppress around].each do |cancellation|
    it "terminates #{cancellation} cancellation without a false delivery or a later resend" do
      row = issue
      raw = service.delivery_token(digest: row.digest)
      events = []
      subscriber = ActiveSupport::Notifications.subscribe("delivery_cancelled.add_auth") { |*args| events << args.last }
      callback = case cancellation
      when :abort then -> { throw :abort }
      when :suppress then -> { message.perform_deliveries = false }
      when :around then ->(_mailer, _block) { true }
      end
      kind = (cancellation == :around) ? :around : :before
      AddAuth::SignInMailer.set_callback(:deliver, kind, callback)
      AddAuth::EmailDeliveryJob.new.perform(row.id)
      expect(ActionMailer::Base.deliveries).to be_empty
      expect(row.reload.delivered_at).to be_nil
      expect(row.revoked_at).to be_present
      expect(row.delivery_payload).to be_nil
      expect(row.delivery_lease_key).to be_nil
      expect(events).to eq([{issuance_id: row.id}])
      expect(service.preview(token: raw)).to be_nil
      AddAuth::SignInMailer.skip_callback(:deliver, kind, callback)
      callback = nil
      AddAuth::EmailDeliveryJob.new.perform(row.id)
      expect(ActionMailer::Base.deliveries).to be_empty
    ensure
      AddAuth::SignInMailer.skip_callback(:deliver, kind, callback) if callback
      ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
    end
  end

  it "honors a Mail interceptor's per-message suppression" do
    row = issue
    interceptor = Class.new do
      def self.delivering_email(message)
        message.perform_deliveries = false
      end
    end
    Mail.register_interceptor(interceptor)
    AddAuth::EmailDeliveryJob.new.perform(row.id)
    expect(ActionMailer::Base.deliveries).to be_empty
    expect(row.reload.delivered_at).to be_nil
    expect(row.revoked_at).to be_present
  ensure
    Mail.unregister_interceptor(interceptor) if interceptor
  end

  it "refuses delivery with suppressed errors and leaves the same intent retryable" do
    row = issue
    callback = -> { message.raise_delivery_errors = false }
    AddAuth::SignInMailer.set_callback(:deliver, :before, callback)
    expect { AddAuth::EmailDeliveryJob.new.perform(row.id) }.to raise_error(AddAuth::Error, /report delivery errors/)
    expect(row.reload.delivered_at).to be_nil
    expect(row.revoked_at).to be_nil
    expect(row.delivery_payload).to be_present
    expect(row.delivery_lease_key).to be_nil
    expect(ActionMailer::Base.deliveries).to be_empty
  ensure
    AddAuth::SignInMailer.skip_callback(:deliver, :before, callback) if callback
  end
end
