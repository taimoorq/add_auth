# frozen_string_literal: true

require "rspec/autorun"
require_relative "../support/browser"

RSpec.describe "Installed authentication key contracts" do
  let(:runtime) { AddAuth::Rails::Runtime }
  let(:service) { runtime.sessions }
  let(:user) { User.create!(email_address: "keys-#{SecureRandom.hex(8)}@example.test", password: "correct-password") }

  before { AddAuth.configuration.rate_limit_store.clear }
  after { Current.reset }

  it "paginates tied creation times, keeps account scope and rejects malformed IDs before querying" do
    current = service.start(user: user, method: :password)
    timestamp = Time.now.utc.change(usec: 123456)
    rows = 53.times.map do
      row = service.start(user: user, method: :password).session
      row.update!(created_at: timestamp)
      row
    end
    first = service.list_page(user: user, current_session_id: current.session.id)
    expect(first.entries.first.id).to eq(current.session.id)
    rows.first.update!(last_seen_at: Time.now)
    # Removing the boundary row must not invalidate the continuation.
    boundary = first.entries.last.id
    Session.find(boundary).destroy!
    second = service.list_page(user: user, current_session_id: current.session.id, before: first.next_cursor)
    expect((first.entries.drop(1) + second.entries).map(&:id)).to eq(rows.map(&:id).sort.reverse)
    expect(second.next_cursor).to be_nil
    foreign = User.create!(email_address: "foreign-#{SecureRandom.hex(8)}@example.test", password: "correct-password")
    grant = service.start(user: foreign, method: :password)
    expect(service.revoke_one(user: user, session: current.session, session_id: grant.session.id)).to be(false)
    expect(grant.session.reload.revoked_at).to be_nil
    malformed = ["not-an-id", "1 OR 1=1", "9" * 100, {}, [], "\xff".b]
    malformed << ((Session.columns_hash.fetch("id").type == :uuid) ? "1" : "123e4567-e89b-42d3-a456-426614174000")
    malformed.each do |id|
      expect(service.revoke_one(user: user, session: current.session, session_id: id)).to be(false)
      expect(service.list_page(user: user, before: id).entries).to be_empty
    end
    target = rows.find { |row| row.id != boundary }
    expect(service.revoke_one(user: user, session: current.session, session_id: target.id.to_s)).to be(true)
    expect(target.reload.revoked_at).to be_present
    expect(service.current_session?(session: current.session, session_id: current.session.id.to_s)).to be(true)
    remaining = rows.find { |row| row.id != boundary && row.id != target.id }
    Session.where(id: current.session.id).update_all(revoked_at: Time.now)
    expect(service.revoke_one(user: user, session: current.session, session_id: remaining.id)).to be(false)
    expect(remaining.reload.revoked_at).to be_nil
  end

  it "adopts a stock signed session ID once under concurrent requests, only within the explicit bridge" do
    row = user.sessions.create!
    expect(service.resume(signed_value: row.id)).to be_nil
    deadline = Time.now + 600
    bridge = AddAuth::Core::Sessions.new(store: AddAuth::Rails::Stores::Sessions.new(user_model: User, session_model: Session),
      digest: AddAuth.configuration.session_token_digest, eligible: ->(_) { true }, legacy_bridge_until: deadline)
    ready, go = Queue.new, Queue.new
    threads = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          bridge.resume(signed_value: row.id)
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    grants = threads.map(&:value).compact
    expect(grants.size).to eq(1)
    expect(grants.first.session.authenticated_with).to be_nil
    expect(bridge.resume(signed_value: row.id)).to be_nil
    expect(service.resume(signed_value: grants.first.bearer).session.id).to eq(row.id)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "retains email proof ownership, consumption and UUID delivery records" do
    runtime.email.issue(identifier: user.email_address)
    row = AddAuthSignInToken.find_by!(user_id: user.id)
    delivery = runtime.email.claim_delivery(digest: row.digest)
    result = runtime.email.consume(token: delivery.fetch(:token)) do |account, persist|
      service.create_in_transaction(user: account, method: :email_link, persist: persist).session
    end
    expect(result).to be_success
    expect(result.session.user_id).to eq(user.id)
    expect(runtime.email.consume(token: delivery.fetch(:token)) { raise "replay finalized a session" }).to be_failure
    user.update!(password: "replacement-password")
    expect(AddAuthSecurityEvent.where(user_id: user.id)).to exist
  end

  it "lists and revokes mobile UUID sessions through the JSON API" do
    client = ActionDispatch::Integration::Session.new(Rails.application)
    client.post "/mobile/session", params: {email_address: user.email_address, password: "correct-password", client_id: "android"}, as: :json
    expect(client.response.status).to eq(201)
    payload = client.response.parsed_body
    headers = {"Authorization" => "Bearer #{payload.fetch("token")}"}
    second = service.start(user: user, method: :password, transport: :mobile, client_id: "android")
    client.get "/mobile/sessions", headers: headers
    expect(client.response.status).to eq(200)
    expect(client.response.body).to include(second.session.id.to_s)
    client.delete "/mobile/sessions/#{second.session.id}", headers: headers
    expect(client.response.status).to eq(204)
    expect(second.session.reload.revoked_at).to be_present
    client.get "/mobile/session", headers: headers
    expect(client.response.status).to eq(200)
  end

  it "binds real WebAuthn registration, step-up and sign-in to typed sessions and credentials" do
    config = AddAuth.configuration
    previous = [config.passkeys.rp_id, config.passkeys.origins, config.turbo_enabled]
    config.turbo_enabled = false
    browser = Capybara::Session.new(:add_auth_chrome, Rails.application)
    origin = "http://localhost:#{browser.server.port}"
    config.passkeys.rp_id = "localhost"
    config.passkeys.origins = [origin]
    browser.driver.browser.execute_cdp("Page.addScriptToEvaluateOnNewDocument",
      source: "Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', {value: async () => false, configurable: true})")
    browser.driver.browser.add_virtual_authenticator(Selenium::WebDriver::VirtualAuthenticatorOptions.new(
      protocol: :ctap2, transport: :internal, resident_key: true, user_verification: true, user_verified: true
    ))
    browser.visit "#{origin}/sign-in"
    browser.fill_in "Email address", with: user.email_address
    browser.fill_in "Password", with: "correct-password"
    browser.click_button "Sign in with password"
    expect(browser).to have_text("Signed in")
    browser.visit "#{origin}/passkeys"
    browser.click_button "Add a passkey"
    expect(browser).to have_text("Verify it’s you")
    browser.fill_in "Current password", with: "correct-password"
    browser.click_button "Verify with password"
    expect(browser).to have_text("Your passkeys")
    browser.click_button "Add a passkey"
    expect(browser).to have_css("h2", text: "Passkey", exact_text: true)
    expect(AddAuthCredential.where(user_id: user.id).count).to eq(1)
    expect(AddAuthCeremony.where(user_id: user.id, consumed_at: nil).count).to eq(0)
    browser.visit "#{origin}/sessions"
    browser.click_button "Sign out", exact: true
    expect(browser).to have_css("h1", text: "Sign in", exact_text: true)
    browser.click_button "Sign in with a passkey"
    expect(browser).to have_text("Signed in")
    expect(Session.where(user_id: user.id, revoked_at: nil).sole.authenticated_with).to eq("passkey")
  ensure
    browser&.quit
    config.passkeys.rp_id, config.passkeys.origins, config.turbo_enabled = previous if previous
  end

  %i[turbo html no_js].each do |mode|
    it "signs in, paginates, revokes and signs out through #{mode} navigation" do
      original_turbo = AddAuth.configuration.turbo_enabled
      original_csrf = ActionController::Base.allow_forgery_protection
      AddAuth.configuration.turbo_enabled = mode == :turbo
      ActionController::Base.allow_forgery_protection = true
      browser = Capybara::Session.new((mode == :no_js) ? :add_auth_no_js : :add_auth_chrome, Rails.application)
      browser.visit "/sign-in"
      expect(browser.evaluate_script("typeof window.Turbo")).to eq((mode == :turbo) ? "object" : "undefined") unless mode == :no_js
      browser.fill_in "Email address", with: user.email_address
      browser.fill_in "Password", with: "correct-password"
      browser.click_button "Sign in with password"
      expect(browser).to have_text("Signed in")
      current = Session.find_by!(user_id: user.id)
      rows = 52.times.map { |i| service.start(user: user, method: :password, user_agent: "Key browser #{i}").session }
      browser.visit "/sessions"
      expect(browser).to have_text("This browser")
      expect(browser).to have_css('meta[name="turbo-cache-control"][content="no-cache"]', visible: :all)
      browser.click_link "Older sessions"
      expect(browser).to have_css("p", text: "Key browser 0", exact_text: true)
      expect(browser).not_to have_text("This browser")
      browser.within("#session_#{rows.first.id}") { browser.click_button "Revoke" }
      expect(browser).to have_text("This browser")
      expect(rows.first.reload.revoked_at).to be_present
      browser.within("#session_#{current.id}") { browser.click_button "Sign out" }
      expect(browser).to have_current_path("/sign-in")
      expect(current.reload.revoked_at).to be_present
      browser.visit "/sessions"
      expect(browser).to have_current_path("/sign-in")
    ensure
      browser&.quit
      AddAuth.configuration.turbo_enabled = original_turbo
      ActionController::Base.allow_forgery_protection = original_csrf
    end
  end
end
