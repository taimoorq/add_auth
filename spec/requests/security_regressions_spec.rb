# frozen_string_literal: true

# Regressions promoted from the independent security audit.
require "rails_helper"

RSpec.describe "Authentication audit regression probes", type: :request, database: true do
  let!(:user) { User.create!(email_address: "audit@example.test", password: "correct-password") }
  let(:runtime) { Latchkey::Rails::Runtime }

  def csrf_form(path)
    get path
    Nokogiri::HTML(response.body).at_css('input[name="authenticity_token"]')&.[]("value")
  end

  it "A01 applies configured challenge policy to the original Rails endpoint" do
    config = Latchkey.configuration
    old_challenge, old_actions = config.challenge, config.challenge_on
    config.challenge = Latchkey::Core::Challenge::Test.new(mode: :rejected)
    config.challenge_on = [:sign_in]
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    csrf = csrf_form("/session/new")
    post "/session", params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
    expect(Session.count).to eq(0), "original POST /session created #{Session.count} session(s) with rejected captcha; HTTP #{response.status}"
  ensure
    config.challenge, config.challenge_on = old_challenge, old_actions
    ActionController::Base.allow_forgery_protection = previous
  end

  it "A02 throttles repeated password guesses on revoke-all" do
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    statuses = 8.times.map do
      post "/sessions/revoke-all", params: {password: "wrong"}
      response.status
    end
    expect(statuses).to include(429), "eight guesses all reached verification: #{statuses.inspect}"
  end

  it "A03 bounds a grant by proof freshness rather than minting a new full window" do
    now = Time.now
    clock = double(now: now)
    proof = Latchkey::Core::StepUp::Evidence.new(user_id: user.id, session_id: 42, method: :password, verified_at: now - 599, session_digest: "generation-1", credential_version: user.password_digest)
    result = Latchkey::Core::StepUp.new(clock: clock, purposes: {manage_profile: {methods: [:password]}})
      .authorize(user: user, session_id: 42, purpose: :manage_profile, evidence: proof)
    expect(result.credential.expires_at).to be <= now + 1
  end

  it "A04 rejects strong evidence without a credential identity" do
    now = Time.now
    proof = Latchkey::Core::StepUp::Evidence.new(user_id: user.id, session_id: 42, method: :passkey, verified_at: now,
      user_verification: true, credential_id: nil)
    result = Latchkey::Core::StepUp.new(purposes: {manage_passkeys: {methods: [:passkey], require_passkey: true}})
      .authorize(user: user, session_id: 42, purpose: :manage_passkeys, evidence: proof)
    expect(result).to be_failure
  end

  def authorized_grant(session, purpose: :manage_profile, clock: Time)
    proof = Latchkey::Core::StepUp::Evidence.new(user_id: user.id, session_id: session.id, method: :password, verified_at: clock.now, session_digest: session.token_digest, credential_version: user.password_digest)
    result = Latchkey::Core::StepUp.new(clock: clock, purposes: {purpose => {methods: [:password]}})
      .authorize(user: user, session_id: session.id, purpose: purpose, evidence: proof)
    expect(result).to be_success
    result.credential
  end

  it "A05 rejects step-up when the current account became ineligible" do
    initial = runtime.sessions.start(user: user, method: :password)
    grant = authorized_grant(initial.session)
    original = Latchkey.configuration.eligible
    Latchkey.configuration.eligible = ->(_) { false }
    expect(runtime.sessions.rotate_for_step_up(user: user, session: initial.session, grant: grant)).to be_nil
  ensure
    Latchkey.configuration.eligible = original
  end

  it "A06 rechecks time after waiting for the account transaction" do
    now = Time.now
    clock = double(now: now)
    store = Latchkey::Rails::Stores::Sessions.new(user_model: User, session_model: Session)
    service = Latchkey::Core::Sessions.new(store: store, digest: Latchkey.configuration.session_token_digest,
      eligible: ->(_) { true }, clock: clock)
    initial = service.start(user: user, method: :password)
    grant = authorized_grant(initial.session, clock: clock)
    allow(store).to receive(:with_session).and_wrap_original do |original, **args, &block|
      original.call(**args) do |account, row|
        allow(clock).to receive(:now).and_return(now + 601)
        block.call(account, row)
      end
    end
    expect(service.rotate_for_step_up(user: user, session: initial.session, grant: grant)).to be_nil
  end

  it "A07 rejects revoke-all from an expired initiating session" do
    initial = runtime.sessions.start(user: user, method: :password)
    grant = authorized_grant(initial.session, purpose: :sign_out_everywhere)
    initial.session.update!(expires_at: 1.second.ago)
    expect(runtime.sessions.revoke_all(user: user, session: initial.session, grant: grant)).to be(false)
  end

  it "A08 filters every accepted provider token parameter" do
    filter = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
    filtered = filter.filter({"challenge_token" => "audit-secret", "cf-turnstile-response" => "audit-secret", "g-recaptcha-response" => "audit-secret"})
    expect(filtered.values).to all(eq("[FILTERED]"))
  end

  it "A09 fails closed after email strategy is disabled without requiring route removal" do
    old_enabled = Latchkey.configuration.email_link.enabled
    Latchkey.configuration.email_link.enabled = false
    post "/sign-in/email", params: {email_address: user.email_address}
    expect(ActiveJob::Base.queue_adapter.enqueued_jobs).to be_empty
  ensure
    Latchkey.configuration.email_link.enabled = old_enabled
  end

  it "A10 gives a Turbo stream validation response on revoke-all" do
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password"}
    post "/sessions/revoke-all", params: {password: "wrong"}, headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response.media_type).to eq("text/vnd.turbo-stream.html")
    expect(response.body).to include("<turbo-stream")
  end
end

RSpec.describe "All password entry points", type: :request, database: true do
  let!(:user) { User.create!(email_address: "entry@example.test", password: "correct-password") }
  around do |example|
    config = Latchkey.configuration
    old = [config.challenge, config.challenge_on, config.challenge_when_unavailable, ActionController::Base.allow_forgery_protection]
    ActionController::Base.allow_forgery_protection = true
    example.run
  ensure
    config.challenge, config.challenge_on, config.challenge_when_unavailable, ActionController::Base.allow_forgery_protection = old
  end

  def token
    get "/sign-in"
    Nokogiri::HTML(response.body).at_css('meta[name="csrf-token"]')["content"]
  end

  %w[/session /sign-in/password].each do |path|
    it "enforces CSRF and closed challenge policy at #{path}" do
      config = Latchkey.configuration
      config.challenge_on = [:sign_in]
      config.challenge = Latchkey::Core::Challenge::Test.new(mode: :success)
      post path, params: {email_address: user.email_address, password: "correct-password"}
      expect(response.status).to eq(422)
      expect(Session.count).to eq(0)
      csrf = token
      %i[rejected unavailable].each do |state|
        config.challenge = Latchkey::Core::Challenge::Test.new(mode: state)
        post path, params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
        expect(response.status).to eq((state == :rejected) ? 422 : 503)
        expect(Session.count).to eq(0)
      end
    end
  end

  it "shares the normalized account guess budget across legacy and new password URLs" do
    csrf = token
    5.times do |attempt|
      post attempt.even? ? "/session" : "/sign-in/password", params: {email_address: " ENTRY@example.test ", password: "wrong", authenticity_token: csrf}
      expect(response.status).to eq(422)
    end
    expect(User).not_to receive(:authenticate_by)
    post "/session", params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
    expect(response.status).to eq(429)
    expect(Session.count).to eq(0)
  end

  it "keeps the account budget across a five-minute boundary with plain HTML and real CSRF" do
    boundary = Time.at((Time.now.to_i / 300 + 1) * 300)
    allow(Time).to receive(:now).and_return(boundary - 1)
    csrf = token
    5.times do
      post "/sign-in/password", params: {email_address: user.email_address, password: "wrong", authenticity_token: csrf}
      expect(response.status).to eq(422)
    end
    allow(Time).to receive(:now).and_return(boundary + 1)
    expect(User).not_to receive(:authenticate_by)
    post "/session", params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
    expect(response.status).to eq(429)
    expect(Session.count).to eq(0)
  end

  it "returns stream errors and emits bypass only for the configured open outage policy" do
    config = Latchkey.configuration
    config.challenge = Latchkey::Core::Challenge::Test.new(mode: :unavailable)
    config.challenge_on = [:sign_in]
    events = []
    subscriber = ActiveSupport::Notifications.subscribe("challenge_bypass.latchkey") { |*args| events << args.last }
    csrf = token
    post "/session", params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf},
      headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response.status).to eq(503)
    expect(response.media_type).to eq("text/vnd.turbo-stream.html")
    expect(events).to be_empty
    config.challenge_when_unavailable = :open
    post "/session", params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
    expect(response.status).to eq(303)
    expect(events).to eq([{action: :sign_in}])
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
  end

  it "redacts supported captcha aliases from real request logs" do
    config = Latchkey.configuration
    config.challenge = Latchkey::Core::Challenge::Test.new(mode: :rejected)
    config.challenge_on = [:sign_in]
    io = StringIO.new
    previous = ActionController::Base.logger
    ActionController::Base.logger = ActiveSupport::Logger.new(io)
    csrf = token
    %w[challenge_token cf-turnstile-response g-recaptcha-response].each do |parameter|
      post "/sign-in/password", params: {:email_address => user.email_address, :password => "correct-password", :authenticity_token => csrf, parameter => "synthetic-secret-#{parameter}"}
    end
    expect(io.string).to include("[FILTERED]")
    expect(io.string).not_to include("synthetic-secret", "correct-password")
  ensure
    ActionController::Base.logger = previous
  end
  it "issues host-only Secure, HttpOnly and SameSite cookies over HTTPS" do
    https!
    csrf = token
    post "/sign-in/password", params: {email_address: user.email_address, password: "correct-password", authenticity_token: csrf}
    expect(response.status).to eq(303)
    header = response.headers["Set-Cookie"].to_s.downcase
    expect(header).to include("session_id=", "secure", "httponly", "samesite=lax", "path=/")
    expect(header).not_to include("domain=")
  ensure
    https!(false)
  end
end
