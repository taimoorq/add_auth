# frozen_string_literal: true

require "rails_helper"

RSpec.describe AddAuth::Core::Sessions, database: true do
  let!(:user) { User.create!(email_address: "person@example.test", password: "correct-password") }
  let(:store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  let(:digest) { AddAuth.configuration.session_token_digest }
  let(:now) { Time.now.change(usec: 0) }
  let(:clock) { double(now: now) }
  let(:deadline) { now + 600 }
  let(:eligible) { ->(_) { true } }
  let(:service) { described_class.new(store: store, digest: digest, eligible: eligible, clock: clock, legacy_bridge_until: deadline) }

  it "stores only a digest, resumes, throttles touches and revokes" do
    grant = service.start(user: user, method: :password)
    expect(grant.bearer).to match(described_class::PATTERN)
    expect(grant.inspect).not_to include(grant.bearer)
    expect(grant.session.token_digest).to eq(digest.digest(grant.bearer))
    expect(service.resume(signed_value: grant.bearer).session.id).to eq(grant.session.id)
    allow(clock).to receive(:now).and_return(now + 61)
    expect(service.resume(signed_value: grant.bearer).session.last_seen_at).to eq(now + 61)
    expect(grant.session.reload.expires_at).to eq(now + 43_200)
    service.revoke(session: grant.session)
    expect(service.resume(signed_value: grant.bearer)).to be_nil
  end

  it "upgrades an existing signed ID once without inventing proof strength" do
    row = user.sessions.create!
    grant = service.resume(signed_value: row.id)
    expect(grant.session.id).to eq(row.id)
    expect(Session.count).to eq(1)
    expect(grant.session.authenticated_with).to be_nil
    expect(grant.session.authenticated_at).to be_nil
    expect(grant.session.expires_at).to eq(deadline)
    expect(service.resume(signed_value: row.id)).to be_nil
    expect(service.resume(signed_value: grant.bearer)).to be_present
  end

  it "rejects legacy cookies by default, at cutoff, or after revocation" do
    row = user.sessions.create!
    default = described_class.new(store: store, digest: digest, eligible: eligible)
    expect(default.resume(signed_value: row.id)).to be_nil
    row.update!(revoked_at: now)
    expect(service.resume(signed_value: row.id)).to be_nil
    row.update!(revoked_at: nil)
    allow(clock).to receive(:now).and_return(deadline)
    expect(service.resume(signed_value: row.id)).to be_nil
  end

  it "never falls back from malformed/new bearer values to predictable IDs" do
    row = user.sessions.create!
    [row.id.to_s, "lk1:#{row.id}", "lk1:" + "x" * 43, nil, {}, -1].each do |value|
      expect(service.resume(signed_value: value)).to be_nil
    end
    expect(row.reload.token_digest).to be_nil
  end

  it "enforces exact idle/absolute expiry and current account eligibility" do
    grant = service.start(user: user, method: :email_link)
    allow(clock).to receive(:now).and_return(now + 1800)
    expect(service.resume(signed_value: grant.bearer)).to be_nil
    grant.session.update!(last_seen_at: now + 43_199)
    allow(clock).to receive(:now).and_return(now + 43_200)
    expect(service.resume(signed_value: grant.bearer)).to be_nil
    blocked = described_class.new(store: store, digest: digest, eligible: ->(_) { false }, clock: clock)
    expect(blocked.start(user: user, method: :password)).to be_nil
  end

  it "serializes simultaneous legacy upgrades on separate database connections" do
    row = user.sessions.create!
    gate, ready = Queue.new, Queue.new
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          gate.pop
          service.resume(signed_value: row.id)
        end
      end
    end
    2.times { ready.pop }
    2.times { gate << true }
    grants = threads.map(&:value).compact
    expect(grants.size).to eq(1)
    expect(row.reload.token_digest).to eq(digest.digest(grants.first.bearer))
  end

  it "denies external, encoded and unsafe return destinations" do
    ["//evil.test", "https://evil.test", "/\\evil.test", "/%2f%2fevil.test", "/\nlocation", nil].each do |value|
      expect(described_class.safe_return(value)).to be_nil
    end
    expect(described_class.safe_return("/settings?tab=profile")).to eq("/settings?tab=profile")
  end
  it "rejects a password proof verified before a concurrent password reset" do
    previously_verified = User.authenticate_by(email_address: user.email_address, password: "correct-password")
    user.update!(password: "new-password")
    expect(service.start(user: previously_verified, method: :password)).to be_nil
    expect(Session.count).to eq(0)
  end

  it "lists only active sessions with display-safe metadata and marks the current one" do
    current = service.start(user: user, method: :password, user_agent: "Browser/1", ip_address: "127.0.0.1")
    other = service.start(user: user, method: :email_link, user_agent: "Other/2", ip_address: "192.0.2.2")
    expired = service.start(user: user, method: :password)
    expired.session.update!(expires_at: now - 1)
    service.revoke(session: other.session)

    entries = service.list(user: user, current_session_id: current.session.id)
    expect(entries.map(&:id)).to eq([current.session.id])
    expect(entries.first.current).to be(true)
    expect(entries.first.user_agent).to eq("Browser/1")
    expect(entries.first).not_to respond_to(:token_digest)
  end

  it "revokes one session only when it belongs to the account" do
    other_user = User.create!(email_address: "other@example.test", password: "other-password")
    owned = service.start(user: user, method: :password)
    initiating = service.start(user: user, method: :password)
    foreign = service.start(user: other_user, method: :password)

    expect(service.revoke_one(user: user, session: initiating.session, session_id: owned.session.id)).to be(true)
    expect(service.resume(signed_value: owned.bearer)).to be_nil
    expect(service.revoke_one(user: user, session: initiating.session, session_id: foreign.session.id)).to be(false)
    expect(foreign.session.reload.revoked_at).to be_nil
    expect(service.revoke_one(user: user, session: initiating.session, session_id: "not-an-id")).to be(false)
  end

  it "revokes every active session only with a bound fresh sign-out grant" do
    current = service.start(user: user, method: :password)
    other = service.start(user: user, method: :email_link)
    step_up = AddAuth::Core::StepUp.new(clock: clock,
      purposes: {sign_out_everywhere: {methods: [:password]}})
    evidence = AddAuth::Core::StepUp::Evidence.new(user_id: user.id, session_id: current.session.id,
      method: :password, verified_at: now - 30, session_digest: current.session.token_digest, credential_version: user.password_digest)
    grant = step_up.authorize(user: user, session_id: current.session.id,
      purpose: :sign_out_everywhere, evidence: evidence).credential

    expect(service.revoke_all(user: user, session: current.session, grant: grant)).to eq(2)
    expect(service.resume(signed_value: current.bearer)).to be_nil
    expect(service.resume(signed_value: other.bearer)).to be_nil
  end

  it "does not let a grant for another purpose revoke sessions" do
    current = service.start(user: user, method: :password)
    other = service.start(user: user, method: :email_link)
    step_up = AddAuth::Core::StepUp.new(clock: clock,
      purposes: {manage_profile: {methods: [:password]}})
    evidence = AddAuth::Core::StepUp::Evidence.new(user_id: user.id, session_id: current.session.id,
      method: :password, verified_at: now - 30, session_digest: current.session.token_digest, credential_version: user.password_digest)
    grant = step_up.authorize(user: user, session_id: current.session.id,
      purpose: :manage_profile, evidence: evidence).credential

    expect(service.revoke_all(user: user, session: current.session, grant: grant)).to be(false)
    expect(service.resume(signed_value: current.bearer)).to be_present
    expect(service.resume(signed_value: other.bearer)).to be_present
  end

  it "rotates the bearer and records a valid step-up grant atomically" do
    initial = service.start(user: user, method: :password)
    step_up = AddAuth::Core::StepUp.new(clock: clock,
      purposes: {manage_profile: {methods: [:password]}})
    evidence = AddAuth::Core::StepUp::Evidence.new(user_id: user.id, session_id: initial.session.id,
      method: :password, verified_at: now - 30, session_digest: initial.session.token_digest, credential_version: user.password_digest)
    result = step_up.authorize(user: user, session_id: initial.session.id,
      purpose: :manage_profile, evidence: evidence)

    rotated = service.rotate_for_step_up(user: user, session: initial.session, grant: result.credential)
    expect(rotated.bearer).not_to eq(initial.bearer)
    expect(service.resume(signed_value: initial.bearer)).to be_nil
    expect(service.resume(signed_value: rotated.bearer)).to be_present
    expect(rotated.session.reload).to have_attributes(elevated_with: "password", elevation_purpose: "manage_profile",
      elevation_uv: false, elevated_at: now - 30)
  end

  it "does not rotate a revoked or expired session even with a previously valid grant" do
    initial = service.start(user: user, method: :password)
    step_up = AddAuth::Core::StepUp.new(clock: clock,
      purposes: {manage_profile: {methods: [:password]}})
    evidence = AddAuth::Core::StepUp::Evidence.new(user_id: user.id, session_id: initial.session.id,
      method: :password, verified_at: now - 30, session_digest: initial.session.token_digest, credential_version: user.password_digest)
    grant = step_up.authorize(user: user, session_id: initial.session.id,
      purpose: :manage_profile, evidence: evidence).credential
    initial.session.update!(revoked_at: now)
    expect(service.rotate_for_step_up(user: user, session: initial.session, grant: grant)).to be_nil
  end
end

RSpec.describe "Step-up finalization races", database: true do
  let!(:user) { User.create!(email_address: "authority@example.test", password: "correct-password") }
  let(:store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  let(:now) { Time.now.change(usec: 0) }
  let(:clock) { double(now: now) }
  let(:service) { AddAuth::Core::Sessions.new(store: store, digest: AddAuth.configuration.session_token_digest, eligible: AddAuth.configuration.eligible, clock: clock) }
  let(:initial) { service.start(user: user, method: :password) }

  def authorize(purpose = :manage_profile)
    proof = AddAuth::Core::StepUp::Evidence.new(user_id: user.id, session_id: initial.session.id,
      session_digest: initial.session.token_digest, credential_version: user.password_digest, method: :password, verified_at: now - 10)
    policy = AddAuth::Core::StepUp.new(clock: clock, purposes: {purpose => {methods: [:password]}})
    result = policy.authorize(user: user, session_id: initial.session.id, purpose: purpose, evidence: proof)
    expect(result).to be_success
    result.credential
  end

  it "permits only one simultaneous rotation and refuses replay of the old grant" do
    grant = authorize
    ready, go = Queue.new, Queue.new
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          service.rotate_for_step_up(user: user, session: initial.session, grant: grant)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    winners = threads.map(&:value).compact
    expect(winners.size).to eq(1)
    expect(service.resume(signed_value: initial.bearer)).to be_nil
    expect(service.resume(signed_value: winners.first.bearer)).to be_present
    expect(service.rotate_for_step_up(user: user, session: winners.first.session, grant: grant)).to be_nil
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "rejects changed credential state even when a direct update skipped lifecycle callbacks" do
    grant = authorize
    user.update_column(:password_digest, BCrypt::Password.create("replacement").to_s)
    expect(service.rotate_for_step_up(user: user, session: initial.session, grant: grant)).to be_nil
  end

  it "rechecks revoke-all expiry, idle timeout and revocation after locking" do
    %i[expires_at last_seen_at revoked_at].each do |attribute|
      row = initial.session
      grant = authorize(:sign_out_everywhere)
      original = row.public_send(attribute)
      row.update_column(attribute, (attribute == :last_seen_at) ? now - 1800 : now)
      expect(service.revoke_all(user: user, session: row, grant: grant)).to be(false)
      row.update_column(attribute, original)
    end
  end

  it "samples the proof expiry inside the revocation transaction" do
    grant = authorize(:sign_out_everywhere)
    allow(store).to receive(:with_session).and_wrap_original do |original, **args, &block|
      original.call(**args) do |account, row|
        allow(clock).to receive(:now).and_return(grant.expires_at)
        block.call(account, row)
      end
    end
    expect(service.revoke_all(user: user, session: initial.session, grant: grant)).to be(false)
    expect(initial.session.reload.revoked_at).to be_nil
  end
end
