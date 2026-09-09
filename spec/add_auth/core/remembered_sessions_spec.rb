# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Remembered browser session policy" do
  let(:now) { Time.utc(2026, 9, 8) }
  let(:clock) { double(now: now) }
  let(:user) { Struct.new(:id, :password_digest).new(1, "current-password-version") }
  let(:digest) { AddAuth::Core::Digest::Hmac.new(salt: "remembered", secret: "secret" * 16) }
  let(:rows) { [] }
  let(:session_type) do
    Struct.new(:id, :user_id, :token_digest, :authenticated_with, :authenticated_at,
      :expires_at, :last_seen_at, :remembered, :idle_timeout, :revoked_at,
      :created_at, :ip_address, :user_agent)
  end
  let(:store) { double }
  let(:profile) { {lifetime: 14 * 86_400, idle_timeout: 7 * 86_400} }
  subject(:sessions) { service(profile) }

  def service(profile)
    AddAuth::Core::Sessions.new(store: store, digest: digest, eligible: ->(_) { true }, clock: clock, remembered_profile: profile)
  end

  before do
    allow(store).to receive(:with_user) { |**_, &block| block.call(user) }
    allow(store).to receive(:with_session) do |**lookup, &block|
      row = rows.find { |candidate| lookup[:digest] ? candidate.token_digest == lookup[:digest] : candidate.id == lookup[:id] }
      block.call(user, row)
    end
    allow(store).to receive(:create) do |user:, **attributes|
      row = session_type.new(**attributes, id: rows.length + 1, user_id: user.id)
      rows << row
      row
    end
    allow(store).to receive(:update) do |row, **attributes|
      attributes.each { |field, value| row.public_send("#{field}=", value) }
    end
    allow(store).to receive(:list_for_user) { |**_| rows }
  end

  it "persists bounded explicit choice and retains ordinary expiry by default" do
    ordinary = sessions.start(user: user, method: :password, remember: "1")
    remembered = sessions.start(user: user, method: :password, remember: true)
    expect(ordinary.session.remembered).to be(false)
    expect(ordinary.session.expires_at).to eq(now + 43_200)
    expect(remembered.session.remembered).to be(true)
    expect(remembered.session.expires_at).to eq(now + 14 * 86_400)
    expect(remembered.session.idle_timeout).to eq(7 * 86_400)
    allow(clock).to receive(:now).and_return(now + 86_400)
    expect(sessions.resume(signed_value: ordinary.bearer)).to be_nil
    expect(sessions.list(user: user).map(&:id)).to eq([remembered.session.id])
    expect(sessions.resume(signed_value: remembered.bearer)).not_to be_nil
  end

  it "honors exact idle and absolute expiry and server-side revocation" do
    remembered = sessions.start(user: user, method: :email_link, remember: true)
    allow(clock).to receive(:now).and_return(now + 7 * 86_400)
    expect(sessions.resume(signed_value: remembered.bearer)).to be_nil
    remembered.session.last_seen_at = now + 14 * 86_400 - 1
    allow(clock).to receive(:now).and_return(now + 14 * 86_400)
    expect(sessions.resume(signed_value: remembered.bearer)).to be_nil
    allow(clock).to receive(:now).and_return(now)
    remembered.session.last_seen_at = now
    sessions.revoke(session: remembered.session)
    expect(sessions.resume(signed_value: remembered.bearer)).to be_nil
  end

  it "applies tighter current policy and refuses malformed stored timeouts" do
    remembered = sessions.start(user: user, method: :password, remember: true)
    allow(clock).to receive(:now).and_return(now + 1800)
    expect(service(nil).resume(signed_value: remembered.bearer)).to be_nil
    expect(service(lifetime: 600, idle_timeout: 300).resume(signed_value: remembered.bearer)).to be_nil
    remembered.session.idle_timeout = nil
    expect(sessions.resume(signed_value: remembered.bearer)).to be_nil
  end

  it "rejects invalid profile durations before authentication can begin" do
    [{lifetime: Float::INFINITY, idle_timeout: 300}, {lifetime: 600, idle_timeout: 601},
      {lifetime: 91 * 86_400, idle_timeout: 600}, {lifetime: 600, idle_timeout: 0}].each do |profile|
      expect { service(profile) }.to raise_error(ArgumentError)
    end
  end
end
