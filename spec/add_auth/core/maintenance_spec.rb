# frozen_string_literal: true

require "spec_helper"

RSpec.describe AddAuth::Core::Maintenance do
  let(:now) { Time.utc(2026, 9, 7) }
  let(:options) { AddAuth::Configuration::MaintenanceOptions.new(batch_size: 2, session_retention: 60) }

  it "supplies bounded cutoffs and reports committed work without purging unconfigured history" do
    sessions = double
    email = double
    expect(sessions).to receive(:purge_expired).with(before: now - 60, now: now, limit: 2).and_return(2)
    expect(email).to receive(:erase_expired_payloads).with(now: now, limit: 2).and_return(1)
    expect(email).to receive(:pending_ids).with(now: now, limit: 2).and_return([7, 8])
    enqueued = []
    result = described_class.new(stores: {session: sessions, email: email}, options: options,
      enqueue: ->(*args) { enqueued << args }, clock: double(now: now)).call
    expect(enqueued).to eq([[:email, 7], [:email, 8]])
    expect(result).to eq(session_deleted: 2, email_payloads_erased: 1, email_enqueued: 2)
  end

  it "purges expired external transactions with the same bounded ceremony contract" do
    external = double
    expect(external).to receive(:purge_expired).with(before: now, now: now, limit: 2).and_return(2)
    result = described_class.new(stores: {external_transaction: external}, options: options,
      enqueue: ->(*) { raise "external transactions are not mail" }, clock: double(now: now)).call
    expect(result).to eq(external_transactions_deleted: 2)
  end

  it "purges native handoffs even with session retention disabled and never treats them as mail" do
    handoffs = double
    expect(handoffs).to receive(:purge_expired).with(before: now, now: now, limit: 2).and_return(2)
    result = described_class.new(stores: {mobile_handoff: handoffs}, options: options,
      enqueue: ->(*) { raise "handoffs are not mail" }, clock: double(now: now)).call
    expect(result).to eq(mobile_handoffs_deleted: 2)
  end

  it "rejects invalid capacity and retention settings before touching a store" do
    [0, -1, 1001, 2.5, nil, "100"].each do |value|
      options.batch_size = value
      expect { described_class.new(stores: {}, options: options, enqueue: nil) }.to raise_error(ArgumentError, /batch_size/)
    end
    options.batch_size = 100
    [-1, Float::INFINITY, Float::NAN, "7 days"].each do |value|
      options.session_retention = value
      expect { described_class.new(stores: {}, options: options, enqueue: nil) }.to raise_error(ArgumentError, /session_retention/)
    end
  end

  it "stops on dispatch failure so the scheduler can retry the same issuance" do
    email = double(erase_expired_payloads: 0, pending_ids: [7, 8])
    enqueued = []
    enqueue = lambda do |_, id|
      enqueued << id
      raise IOError
    end
    service = described_class.new(stores: {email: email}, options: options,
      enqueue: enqueue, clock: double(now: now))
    expect { service.call }.to raise_error(IOError)
    expect(enqueued).to eq([7])
  end
end
