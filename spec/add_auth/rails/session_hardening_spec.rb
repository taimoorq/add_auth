# frozen_string_literal: true

require "rails_helper"
require "timeout"

RSpec.describe "Atomic session replacement and revocation", database: true do
  let!(:user) { User.create!(email_address: "replace@example.test", password: "correct-password") }
  let(:store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  let(:now) { Time.now }
  let(:clock) { double(now: now) }
  let(:service) do
    AddAuth::Core::Sessions.new(store: store, digest: AddAuth.configuration.session_token_digest,
      eligible: ->(account) { account.created_at < clock.now + 3600 }, clock: clock)
  end
  let(:initial) { service.start(user: user, method: :password) }

  it "replaces only the supplied browser and refuses its old bearer" do
    old = initial
    other = service.start(user: user, method: :password)
    replacement = service.start(user: user, method: :password, replacing: old.session)
    expect(service.resume(signed_value: old.bearer)).to be_nil
    expect(service.resume(signed_value: replacement.bearer)).to be_present
    expect(service.resume(signed_value: other.bearer)).to be_present
  end

  it "preserves the old session when replacement creation rolls back" do
    old = initial
    allow(store).to receive(:create).and_raise(ActiveRecord::RecordNotSaved, "injected failure")
    expect { service.start(user: user, method: :password, replacing: old.session) }.to raise_error(ActiveRecord::RecordNotSaved)
    expect(Session.count).to eq(1)
    expect(old.session.reload.revoked_at).to be_nil
    expect(service.resume(signed_value: old.bearer)).to be_present
  end

  it "identifies an ineligible browser for retirement without authenticating or touching it" do
    old = initial
    last_seen = old.session.last_seen_at
    user.update!(created_at: now + 86_400)
    expect(service.resume(signed_value: old.bearer)).to be_nil
    previous = service.replacement_for(signed_value: old.bearer)
    expect(previous.id).to eq(old.session.id)
    expect(old.session.reload.last_seen_at).to eq(last_seen)
    other = User.create!(email_address: "eligible@example.test", password: "other-password")
    service.start(user: other, method: :password, replacing: previous)
    user.update!(created_at: now - 60)
    expect(service.resume(signed_value: old.bearer)).to be_nil
  end

  it "does not revoke a newer bearer generation through a stale replacement or logout snapshot" do
    old = initial
    stale = Session.find(old.session.id)
    old.session.update!(token_digest: AddAuth.configuration.session_token_digest.digest("new-generation"))
    service.start(user: user, method: :password, replacing: stale)
    service.revoke(session: stale)
    expect(old.session.reload.revoked_at).to be_nil
  end

  it "locks opposing account switches in the same order on separate connections" do
    first = initial
    second_user = User.create!(email_address: "switch@example.test", password: "other-password")
    second = AddAuth::Rails::Runtime.sessions.start(user: second_user, method: :password)
    ready, go = Queue.new, Queue.new
    threads = [[second_user, first], [user, second]].map do |target, prior|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          AddAuth::Rails::Runtime.sessions.start(user: target, method: :password, replacing: prior.session)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    replacements = Timeout.timeout(10) { threads.map(&:value) }
    expect(replacements.map { |grant| grant.session.user_id }).to eq([second_user.id, user.id])
    expect(first.session.reload.revoked_at).to be_present
    expect(second.session.reload.revoked_at).to be_present
    expect(Session.where(revoked_at: nil).count).to eq(2)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "keeps email token consumption, prior revocation and replacement creation atomic" do
    old = initial
    other_user = User.create!(email_address: "email-switch@example.test", password: "other-password")
    email = AddAuth::Rails::Runtime.email
    email.issue(identifier: other_user.email_address)
    token = AddAuthSignInToken.last
    raw = email.delivery_token(digest: token.digest)
    allow(Session).to receive(:create!).and_raise(ActiveRecord::RecordNotSaved, "injected failure")
    expect do
      email.consume(token: raw, current_session: old.session, switch_account: true) do |account, persist|
        service.create_in_transaction(user: account, method: :email_link, persist: persist, replacing: old.session)&.session
      end
    end.to raise_error(ActiveRecord::RecordNotSaved)
    expect(token.reload.consumed_at).to be_nil
    expect(token.delivery_payload).to be_present
    expect(old.session.reload.revoked_at).to be_nil
    expect(Session.count).to eq(1)
  end

  %i[revoked expired idle rotated ineligible].each do |change|
    it "denies revoke-one when the initiating authority becomes #{change} after request authentication" do
      current = initial
      target = service.start(user: user, method: :password)
      allow(store).to receive(:with_session).and_wrap_original do |original, **args, &block|
        original.call(**args) do |account, row|
          case change
          when :revoked then row.update!(revoked_at: now)
          when :expired then row.update!(expires_at: now)
          when :idle then allow(clock).to receive(:now).and_return(now + 1800)
          when :rotated then row.update!(token_digest: "new-generation")
          when :ineligible then account.update!(created_at: now + 86_400)
          end
          block.call(account, row)
        end
      end
      expect(service.revoke_one(user: user, session: current.session, session_id: target.session.id)).to be(false)
      expect(target.session.reload.revoked_at).to be_nil
    end
  end

  it "requires a current initiating session belonging to the claimed account" do
    target = initial
    stranger = User.create!(email_address: "stranger@example.test", password: "other-password")
    foreign = AddAuth::Rails::Runtime.sessions.start(user: stranger, method: :password)
    [nil, foreign.session].each do |current|
      expect(service.revoke_one(user: user, session: current, session_id: target.session.id)).to be(false)
    end
    expect(target.session.reload.revoked_at).to be_nil
  end
end
