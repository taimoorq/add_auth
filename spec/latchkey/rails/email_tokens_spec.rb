# frozen_string_literal: true

require "rails_helper"
require_relative "../../support/email_token_contract"

RSpec.describe Latchkey::Rails::Stores::EmailTokens, database: true do
  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }
  let(:store) { described_class.new(user_model: User, token_model: LatchkeySignInToken, session_model: Session) }
  let(:cipher) { Latchkey::Rails::DeliveryCipher.new(key: "d" * 32) }

  def rows = LatchkeySignInToken.order(:id).to_a
  def sessions = Session.all.to_a
  def persist_session(account) = account.sessions.create!
  def disable_user = user.update!(email_address: "disabled@example.test")
  def change_purpose(record) = record.update!(purpose: "recovery")

  include_examples "email token lifecycle"
  include_examples "address-bound email proof"

  def change_address = user.update!(email_address: "changed@example.test")

  it "rolls back consumption and session creation together when the finalizer fails" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect {
      consume_link(raw) do |account|
        account.sessions.create!
        raise "finalization failed"
      end
    }.to raise_error("finalization failed")
    expect(Session.count).to eq(0)
    expect(record.reload.consumed_at).to be_nil
    expect(service.delivery_token(digest: record.digest)).to eq(raw)
    expect(consume_link(raw)).to be_success
  end

  it "never reports success when ActiveRecord swallows a rollback" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect { consume_link(raw) { raise ActiveRecord::Rollback } }
      .to raise_error(Latchkey::Error, /rolled back/)
    expect(record.reload.consumed_at).to be_nil
    expect(Session.count).to eq(0)
  end

  it "rejects a finalizer's session for another user and restores the token" do
    other = User.create!(email_address: "other@example.test", password: "correct-password")
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect { consume_link(raw) { other.sessions.create! } }.to raise_error(Latchkey::Error, /transaction writer/)
    expect(Session.count).to eq(0)
    expect(record.reload.consumed_at).to be_nil
  end

  it "rolls back revocation if replacement intent persistence fails" do
    first = issue_link
    allow(store).to receive(:replace_pending).and_wrap_original do |original, **arguments|
      original.call(**arguments)
      raise "persistence failed"
    end
    expect { issue_link }.to raise_error("persistence failed")
    expect(LatchkeySignInToken.count).to eq(1)
    expect(first.reload.revoked_at).to be_nil
    expect(service.delivery_token(digest: first.digest)).to be_a(String)
  end

  it "denies tampered or swapped encrypted delivery payloads" do
    first = issue_link
    old_payload = first.delivery_payload
    second = issue_link
    second.update!(delivery_payload: old_payload)
    expect(service.delivery_token(digest: second.digest)).to be_nil
    second.update!(delivery_payload: "tampered")
    expect(service.delivery_token(digest: second.digest)).to be_nil
    expect(second.inspect).not_to include(old_payload)
  end

  def race(count = 2)
    ready, start = Queue.new, Queue.new
    threads = count.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do |connection|
          ready << connection.object_id
          start.pop
          yield
        end
      end
    end
    connection_ids = count.times.map { ready.pop }
    expect(connection_ids.uniq.size).to eq(count)
    count.times { start << true }
    threads.map(&:value)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "permits exactly one concurrent consumer on separate database connections" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    service # Resolve RSpec memoization before concurrent execution.
    results = race { consume_link(raw) }
    expect(results.count(&:success?)).to eq(1)
    expect(results.reject(&:success?).map(&:reason)).to eq([:consumed_token])
    expect(Session.count).to eq(1)
  end

  it "leaves one deliverable token after concurrent resends" do
    service
    race { service.issue(identifier: user.email_address) }
    expect(LatchkeySignInToken.count).to eq(2)
    live = LatchkeySignInToken.where(revoked_at: nil, consumed_at: nil)
    expect(live.count).to eq(1)
    expect(service.delivery_token(digest: live.first.digest)).to be_a(String)
  end
  it "rejects success inside an outer transaction that could subsequently roll back" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect {
      User.transaction { consume_link(raw) }
    }.to raise_error(Latchkey::Error, /outer transaction/)
    expect(record.reload.consumed_at).to be_nil
    expect(Session.count).to eq(0)
  end

  it "rejects reuse of an existing session instead of minting fresh authority" do
    existing = user.sessions.create!
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    expect { consume_link(raw) { existing } }.to raise_error(Latchkey::Error)
    expect(record.reload.consumed_at).to be_nil
    expect(Session.count).to eq(1)
  end

  it "requires all authentication models to share a connection pool" do
    other_pool = Class.new(ActiveRecord::Base) do
      self.abstract_class = true
      def self.connection_pool = Object.new
    end
    expect {
      described_class.new(user_model: User, token_model: LatchkeySignInToken, session_model: other_pool)
    }.to raise_error(ArgumentError, /connection pool/)
  end

  it "refuses issuance if the identifier changed before acquiring the account lock" do
    allow(store).to receive(:with_user).and_wrap_original do |original, **arguments, &block|
      original.call(**arguments) do |account|
        account.update!(email_address: "changed@example.test")
        block.call(account)
      end
    end
    service.issue(identifier: user.email_address)
    expect(LatchkeySignInToken.count).to eq(0)
  end

  it "rejects invalid delivery encryption keys at configuration time" do
    [nil, "", "short", "x" * 33].each do |key|
      expect { Latchkey::Rails::DeliveryCipher.new(key: key) }.to raise_error(ArgumentError)
    end
  end
  it "rejects a consumed token even when the request previously cached its state" do
    record = issue_link
    raw = service.delivery_token(digest: record.digest)
    LatchkeySignInToken.cache do
      service.delivery_token(digest: record.digest)
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection { consume_link(raw) }
      end.value
      expect(consume_link(raw).reason).to eq(:consumed_token)
    end
    expect(Session.count).to eq(1)
  end

  it "enforces unique digests and rolls back a colliding replacement" do
    fixed_random = double("random", urlsafe_base64: "a" * 43)
    collision_service = Latchkey::Core::Strategies::EmailLink.new(store: store, digest: digest,
      delivery_cipher: cipher, eligible: ->(_) { true }, normalize_identifier: ->(value) { value },
      identifier_for: ->(account) { account.email_address }, random: fixed_random)
    collision_service.issue(identifier: user.email_address)
    expect { collision_service.issue(identifier: user.email_address) }.to raise_error(ActiveRecord::RecordNotUnique)
    expect(rows.size).to eq(1)
    expect(rows.first.revoked_at).to be_nil
    expect(collision_service.delivery_token(digest: rows.first.digest)).to eq("a" * 43)
  end
end

RSpec.describe "Transaction-owned email session writer", database: true do
  let!(:user) { User.create!(email_address: "writer@example.test", password: "correct-password") }
  let(:service) { Latchkey::Rails::Runtime.email }

  def token
    service.issue(identifier: user.email_address)
    service.delivery_token(digest: LatchkeySignInToken.last.digest)
  end

  it "expires the writer when consumption commits" do
    writer = nil
    result = service.consume(token: token) { |_account, persist|
      writer = persist
      persist.call
    }
    expect(result).to be_success
    expect { writer.call }.to raise_error(Latchkey::Error)
    expect(Session.count).to eq(1)
  end

  it "rolls back duplicate creation and permits a clean retry" do
    raw = token
    expect {
      service.consume(token: raw) { |_account, persist|
        persist.call
        persist.call
      }
    }.to raise_error(Latchkey::Error)
    expect(Session.count).to eq(0)
    expect(LatchkeySignInToken.last.consumed_at).to be_nil
    expect(service.consume(token: raw) { |_account, persist| persist.call }).to be_success
  end
  it "rejects moving the writer to another thread and connection" do
    raw = token
    expect {
      service.consume(token: raw) do |_account, persist|
        Thread.new do
          Thread.current.report_on_exception = false
          ActiveRecord::Base.connection_pool.with_connection { persist.call }
        end.value
      end
    }.to raise_error(Latchkey::Error)
    expect(Session.count).to eq(0)
    expect(LatchkeySignInToken.last.consumed_at).to be_nil
  end
end
