# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Mobile sessions share the account authority", database: true do
  let!(:user) { User.create!(email_address: "mobile@example.test", password: "correct-password") }
  let(:now) { Time.now.change(usec: 0) }
  let(:clock) { double(now: now) }
  let(:store) { AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session) }
  let(:profile) { AddAuth::Core::MobileProfile.new(lifetime: 30 * 86_400, idle_timeout: 14 * 86_400, clients: %w[android ios]) }
  let(:service) { build_service(profile) }

  def build_service(profile, eligible: ->(_) { true })
    AddAuth::Core::Sessions.new(store: store, digest: AddAuth.configuration.session_token_digest,
      eligible: eligible, clock: clock, mobile_profile: profile, access_policy: AddAuth::Rails::Runtime.access_policy)
  end

  def mobile(client = "android") = service.start(user: user, method: :password, transport: :mobile, client_id: client)

  it "stores a digest on the shared Session and never accepts it through a browser parser" do
    grant = mobile
    expect(grant.session).to have_attributes(transport: "mobile", client_id: "android", mobile_idle_timeout: 14 * 86_400,
      expires_at: now + 30 * 86_400, token_digest: AddAuth.configuration.session_token_digest.digest(grant.bearer))
    expect(service.resume(signed_value: grant.bearer)).to be_nil
    expect(service.replacement_for(signed_value: grant.bearer)).to be_nil
    expect(service.resume_mobile(bearer: grant.bearer).session.id).to eq(grant.session.id)
    browser = service.start(user: user, method: :password)
    expect(browser.session.transport).to eq("browser")
    expect(service.resume_mobile(bearer: browser.bearer)).to be_nil
    expect(service.resume(signed_value: browser.bearer)).to be_present
    expect(grant.inspect).not_to include(grant.bearer)
  end

  it "keeps mobile use alive past browser idle while preserving exact mobile expiry" do
    grant = mobile
    allow(clock).to receive(:now).and_return(now + 86_400)
    expect(service.resume_mobile(bearer: grant.bearer)).to be_present
    expect(grant.session.reload.last_seen_at).to eq(now + 86_400)
    expect(grant.session.authenticated_at).to eq(now)
    allow(clock).to receive(:now).and_return(now + 15 * 86_400)
    expect(service.resume_mobile(bearer: grant.bearer)).to be_nil
    grant.session.update!(last_seen_at: now + 30 * 86_400 - 1)
    allow(clock).to receive(:now).and_return(now + 30 * 86_400)
    expect(service.resume_mobile(bearer: grant.bearer)).to be_nil
  end

  it "fails closed when disabled, shortened, unknown-client or current account policy changes" do
    grant = mobile
    expect(build_service(nil).resume_mobile(bearer: grant.bearer)).to be_nil
    expect(build_service(profile, eligible: ->(_) { false }).resume_mobile(bearer: grant.bearer)).to be_nil
    shorter = AddAuth::Core::MobileProfile.new(lifetime: 600, idle_timeout: 300, clients: ["android"])
    allow(clock).to receive(:now).and_return(now + 300)
    expect(build_service(shorter).resume_mobile(bearer: grant.bearer)).to be_nil
    expect(mobile("unregistered")).to be_nil
    expect(service.start(user: user, method: :password, transport: "mobile", client_id: "android")).to be_nil
    user.update_column(:add_auth_strict, true)
    expect(service.resume_mobile(bearer: grant.bearer)).to be_nil
  end

  it "uses the common list and permits a live browser to revoke only its own device" do
    grant = mobile
    allow(clock).to receive(:now).and_return(now + 86_400)
    browser = service.start(user: user, method: :password)
    entries = service.list(user: user, current_session_id: browser.session.id)
    expect(entries.map(&:id)).to contain_exactly(grant.session.id, browser.session.id)
    expect(entries.find { |entry| entry.id == grant.session.id }).to have_attributes(transport: "mobile", client_id: "android")
    expect(service.revoke_one(user: user, session: browser.session, session_id: grant.session.id)).to be(true)
    expect(service.resume_mobile(bearer: grant.bearer)).to be_nil
    expect(service.resume(signed_value: browser.bearer)).to be_present
  end

  it "invalidates every transport after a password change through existing lifecycle wiring" do
    grant = mobile
    browser = service.start(user: user, method: :password)
    user.update!(password: "replacement-password")
    expect(service.resume_mobile(bearer: grant.bearer)).to be_nil
    expect(service.resume(signed_value: browser.bearer)).to be_nil
    expect(grant.session.reload.revoked_at).to be_present
  end

  it "rejects a password proof made before a concurrent reset" do
    previously_verified = User.authenticate_by(email_address: user.email_address, password: "correct-password")
    user.update!(password: "replacement-password")
    expect(service.start(user: previously_verified, method: :password, transport: :mobile, client_id: "android")).to be_nil
    expect(Session.count).to eq(0)
  end

  it "rotates mobile elevation within its own transport and revokes every transport with current proof" do
    grant = mobile
    browser = service.start(user: user, method: :password)
    policy = AddAuth::Core::StepUp.new(clock: clock, purposes: {sign_out_everywhere: {methods: [:password]}})
    result = service.reauthenticate(user: user, session: grant.session, purpose: :sign_out_everywhere, policy: policy) { user }
    expect(result).to be_success
    rotated = service.rotate_for_step_up(user: user, session: grant.session, grant: result.credential)
    expect(rotated.bearer).to match(AddAuth::Core::MobileProfile::PATTERN)
    expect(service.resume_mobile(bearer: grant.bearer)).to be_nil
    expect(service.resume(signed_value: rotated.bearer)).to be_nil
    next_proof = service.reauthenticate(user: user, session: rotated.session, purpose: :sign_out_everywhere, policy: policy) { user }
    expect(service.revoke_all(user: user, session: rotated.session, grant: next_proof.credential)).to eq(2)
    expect(service.resume_mobile(bearer: rotated.bearer)).to be_nil
    expect(service.resume(signed_value: browser.bearer)).to be_nil
  end

  it "serializes revocation with issuance on real database connections" do
    ready, go = Queue.new, Queue.new
    threads = 2.times.map do |i|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          if i.zero?
            mobile
          else
            store.with_user(id: user.id) do |account|
              account.update_columns(add_auth_strict: true)
              AddAuth::Rails::Runtime.authority.revoke(user_id: account.id, at: now)
            end
            nil
          end
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    grants = threads.map(&:value).compact
    grants.each { |grant| expect(service.resume_mobile(bearer: grant.bearer)).to be_nil }
    expect(Session.where(transport: "mobile", revoked_at: nil)).to be_empty
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end
end
