# frozen_string_literal: true

# Executed only in a freshly generated, disposable host by the RSpec wrapper.
require "add_auth/core/account_lifecycle"
require "add_auth/core/account_policy"
require "add_auth/rails/stores/account_tokens"
require "add_auth/rails/stores/external_identities"
require "add_auth/rails/stores/authority"
require "add_auth/rails/stores/sessions"

ActiveJob::Base.queue_adapter = :test
clock = Struct.new(:now).new(Time.now.utc)
policy = AddAuth::Core::AccountPolicy.new(enabled: true, clock: clock)
digest = AddAuth.configuration.sign_in_token_digest
store = AddAuth::Rails::Stores::ExternalIdentities.new(user_model: User, identity_model: AddAuthExternalIdentity, transaction_model: AddAuthExternalTransaction)
authority = AddAuth::Rails::Stores::Authority.new(user_model: User, session_model: Session)
accounts_store = AddAuth::Rails::Stores::AccountTokens.new(user_model: User, token_model: AddAuthAccountToken, session_model: Session,
  address_model: AddAuthAddressClaim, authority: authority, provision: ->(_) {})
verified_type = Struct.new(:claims)
configuration = AddAuth::Core::ExternalIdentities::Configuration.new(id: "fixture", issuer: "https://issuer.test", audience: "browser",
  verifier: ->(server_result:, transaction:) { server_result.claims if server_result.instance_of?(verified_type) })
build_service = ->(**overrides) {
  AddAuth::Core::ExternalIdentities.new(store: store, configurations: [configuration], sessions: nil, access_policy: nil, policy: nil,
    eligible: ->(user) { policy.allowed?(user) }, enrollment_eligible: ->(user) { policy.allowed?(user, purpose: :confirm) },
    digest: digest, revoke_authority: ->(**_) {}, remaining_method: ->(_) { false }, enabled: true, clock: clock, **overrides)
}
service = build_service.call
accounts = AddAuth::Core::AccountLifecycle.new(store: accounts_store, policy: policy, digest: digest,
  delivery_cipher: AddAuth::Rails::DeliveryCipher.new(key: Rails.application.key_generator.generate_key("enrollment-proof-test", 32)),
  password_policy: ->(password) { password.length >= 12 }, trusted_address: ->(user) { user.email_address if user.confirmed_at },
  profile_attributes: ->(profile) { profile.slice(:name, :accepted_terms) }, external_identities: -> { service }, clock: clock)
browser = AddAuth::Core::BrowserBinding.new(digest: digest).generate
profile = {name: "Fixture Person", accepted_terms: true}
issue = ->(subject, purpose = :enroll_external_identity) {
  pending = service.begin_transaction(configuration_id: configuration.id, browser_secret: browser, purpose: purpose).credential
  [pending, configuration.verify(transaction: pending, server_result: verified_type.new({issuer: configuration.issuer,
    audience: configuration.audience, subject: subject, provenance: "fixture-server-v1"}))]
}
register = ->(email, evidence, supplied_profile = profile) { accounts.register_external(identifier: email, evidence: evidence, profile: supplied_profile) }
counts = -> { ActiveRecord::Base.uncached { [User.count, AddAuthAddressClaim.count, AddAuthAccountToken.count, AddAuthExternalIdentity.count, Session.count] } }
assert_unchanged = ->(before) { raise "partial enrollment committed" unless counts.call == before }

pending, proof = issue.call("new-subject")
raise "enrollment was account bound" unless pending.user_id.nil? && pending.session_id.nil? && pending.purpose == :enroll_external_identity
result = register.call(" NEW@example.test ", proof)
raise "registration failed" unless result.success? && result.user.nil?
user = User.find_by!(email_address: "new@example.test")
raise "enrollment fabricated password or confirmation" unless user.password_digest.nil? && user.confirmed_at.nil?
raise "host profile not validated/persisted" unless user.name == profile[:name] && user.accepted_terms
raise "binding missing" unless AddAuthExternalIdentity.find_by!(subject: "new-subject").user_id == user.id
raise "address claim or independent proof missing" unless AddAuthAddressClaim.where(user_id: user.id).count == 1 && AddAuthAccountToken.where(user_id: user.id, purpose: "confirm").count == 1
raise "enrollment granted a session" unless Session.count == 0
raise "unconfirmed account eligible" if policy.allowed?(user)
raise "transaction replayable" if service.pending(transaction: pending.id, browser_secret: browser)

# Closed enrollment policy and disabled features roll back the fresh account.
[[build_service.call(enabled: false), :disabled], [build_service.call(enrollment_eligible: ->(_) { false }), :invalid_credentials]].each_with_index do |(target, reason), index|
  pending, denied_proof = issue.call("denied-#{index}")
  before = counts.call
  begin
    accounts_store.create_account(email: "denied-#{index}@example.test", password: nil, profile: profile) do |account|
      capability = AddAuth::Core::AccountLifecycle::NewAccount.send(:new, user: account)
      target.bind_new_account_in_transaction(registration: capability, evidence: denied_proof)
    end
    raise "enrollment policy was bypassed"
  rescue AddAuth::Core::ExternalIdentities::EnrollmentRejected => error
    raise "wrong policy rejection" unless error.reason == reason
  end
  assert_unchanged.call(before)
  raise "denial burned transaction" unless service.pending(transaction: pending.id, browser_secret: browser)
end

# A real host validation failure must not consume provider proof or create state.
pending, proof = issue.call("invalid-profile")
before = counts.call
raise "host validation bypassed" if register.call("invalid-profile@example.test", proof, {name: "", accepted_terms: false}).success?
assert_unchanged.call(before)
raise "validation burned proof" unless service.pending(transaction: pending.id, browser_secret: browser)

# Wrong-purpose and plain request evidence cannot enroll an account.
_pending, sign_in_proof = issue.call("wrong-purpose", :sign_in)
before = counts.call
raise "sign-in proof enrolled an account" if register.call("wrong-purpose@example.test", sign_in_proof).success?
raise "raw hash enrolled an account" if register.call("hash@example.test", {subject: "forged"}).success?
assert_unchanged.call(before)

# Typed failures escape the fresh-account block, rolling back the actual Rails row.
_, expired_proof = issue.call("expired-subject")
clock.now += 301
before = counts.call
begin
  accounts_store.create_account(email: "expired@example.test", password: nil, profile: profile) do |account|
    capability = AddAuth::Core::AccountLifecycle::NewAccount.send(:new, user: account)
    service.bind_new_account_in_transaction(registration: capability, evidence: expired_proof)
  end
  raise "expired enrollment accepted"
rescue AddAuth::Core::ExternalIdentities::EnrollmentRejected => error
  raise "wrong expiry reason" unless error.reason == :expired_token
end
assert_unchanged.call(before)

pending, conflicting = issue.call("new-subject")
before = counts.call
raise "existing binding moved" if register.call("conflict@example.test", conflicting).success?
assert_unchanged.call(before)
raise "conflict burned transaction" unless service.pending(transaction: pending.id, browser_secret: browser)

# A conflict after binding/CAS must roll those writes back too. Reserve an address
# as pending for the existing user while no User has that address yet.
reserved = "reserved@example.test"
AddAuthAddressClaim.create!(user_id: user.id, digest: digest.digest("account-address:#{reserved}"), state: "pending")
pending, reserved_proof = issue.call("reserved-address-subject")
before = counts.call
register.call(reserved, reserved_proof)
assert_unchanged.call(before)
raise "address conflict committed consumption" unless service.pending(transaction: pending.id, browser_secret: browser)

# Simulate failure after binding and an independent proof insertion. Every row
# and the single-use claim must share the registration transaction.
pending, retry_proof = issue.call("retry-subject")
before = counts.call
begin
  accounts_store.create_account(email: "retry@example.test", password: nil, profile: profile) do |account|
    registration = AddAuth::Core::AccountLifecycle::NewAccount.send(:new, user: account)
    service.bind_new_account_in_transaction(registration: registration, evidence: retry_proof)
    accounts_store.claim_address(user: account, digest: digest.digest("account-address:retry@example.test"), address: "retry@example.test", state: "current")
    accounts.send(:issue_in_transaction, user: account, purpose: "confirm", recipient: "retry@example.test")
    raise "simulated post-bind failure"
  end
rescue RuntimeError => error
  raise unless error.message == "simulated post-bind failure"
end
assert_unchanged.call(before)
raise "rollback burned provider evidence" unless service.pending(transaction: pending.id, browser_secret: browser)
raise "retry failed" unless register.call("retry@example.test", retry_proof).success?
before = counts.call
raise "replay accepted" if register.call("replay@example.test", retry_proof).success?
assert_unchanged.call(before)

# A capability outside an owning transaction cannot consume any proof.
pending, outsider_proof = issue.call("outside-transaction")
capability = AddAuth::Core::AccountLifecycle::NewAccount.send(:new, user: user)
begin
  service.bind_new_account_in_transaction(registration: capability, evidence: outsider_proof)
  raise "enrollment ran outside registration transaction"
rescue AddAuth::Core::ExternalIdentities::EnrollmentRejected => error
  raise "wrong capability rejection" unless error.reason == :invalid_credentials
end
raise "misuse burned transaction" unless service.pending(transaction: pending.id, browser_secret: browser)

race = ->(*operations) {
  ready, gate = Queue.new, Queue.new
  threads = operations.map { |operation|
    Thread.new {
      ActiveRecord::Base.connection_pool.with_connection {
        ready << true
        gate.pop
        operation.call
      }
    }
  }
  operations.size.times { ready.pop }
  operations.size.times { gate << true }
  threads.map(&:value)
}
_pending, raced = issue.call("raced-subject")
before = counts.call
results = race.call(-> { register.call("raced-a@example.test", raced) }, -> { register.call("raced-b@example.test", raced) })
raise "replayed enrollment had multiple winners" unless results.count(&:success?) == 1
raise "replay race orphaned state: before=#{before.inspect} after=#{counts.call.inspect}" unless counts.call == before.zip([1, 1, 1, 1, 0]).map { |a, b| a + b }
_pending, first = issue.call("namespace-race")
_pending, second = issue.call("namespace-race")
before = counts.call
results = race.call(-> { register.call("namespace-a@example.test", first) }, -> { register.call("namespace-b@example.test", second) })
raise "namespace race had multiple owners" unless results.count(&:success?) == 1
raise "namespace race orphaned account or proof: before=#{before.inspect} after=#{counts.call.inspect}" unless counts.call == before.zip([1, 1, 1, 1, 0]).map { |a, b| a + b }
raise "enrollment minted browser authority" unless Session.count == 0
puts "external enrollment and rollback verified"
