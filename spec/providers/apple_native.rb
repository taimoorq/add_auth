# frozen_string_literal: true

require_relative "../support/external_identity_host"
require "jwt"
require "webmock/rspec"
require "add_auth/rails/provider_libraries/apple_native"
require "add_auth/rails/provider_libraries/apple_jwks"

WebMock.disable_net_connect!(allow_localhost: true)

RSpec.describe "Native Apple verification through ruby-jwt", type: :request, database: true do
  let(:config) { AddAuth.configuration }
  let(:key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:key_id) { "native-apple-fixture" }
  let(:jwks) { {"keys" => [JWT::JWK.new(key.public_key, kid: key_id, alg: "RS256", use: "sig").export.transform_keys(&:to_s)]} }
  let!(:user) { User.create!(email_address: "native-apple@example.test", password: "correct-password") }
  let(:provider) do
    AddAuth::Core::ExternalIdentities::Configuration.new(id: "apple-ios", issuer: "https://appleid.apple.com", audience: "com.example.app",
      verifier: AddAuth::Rails::ProviderLibraries::AppleNative::Verifier.new)
  end

  around do |example|
    previous = config.mobile.to_h
    old_external = config.external_identities
    options = AddAuth::Configuration::ExternalIdentityOptions.new
    options.register_native(configuration: provider)
    options.enabled = true
    config.instance_variable_set(:@external_identities, options)
    config.mobile.enabled = true
    config.mobile.lifetime = 30 * 86_400
    config.mobile.idle_timeout = 14 * 86_400
    config.mobile.clients = %w[ios android]
    config.mobile.apple_providers = {"ios" => provider.id}
    example.run
  ensure
    previous.each { |name, value| config.mobile.public_send("#{name}=", value) }
    config.instance_variable_set(:@external_identities, old_external)
    Rails.cache.clear
  end

  before do
    Rails.cache.clear
    AddAuthExternalIdentity.create!(user: user, namespace: provider.namespace("NativeSubject"), provider_id: provider.id,
      issuer: provider.issuer, audience: provider.audience, subject: "NativeSubject", provenance: "reviewed-native-fixture",
      credential_version: "original", linked_at: Time.now - 5)
    stub_request(:get, "https://appleid.apple.com/auth/keys").to_return(status: 200, body: jwks.to_json)
  end

  def challenge
    post "/mobile/apple/challenge", params: {client_id: "ios"}, as: :json
    expect(response).to have_http_status(:created)
    response.parsed_body
  end

  def token(proof, attributes = {}, signing_key: key, algorithm: "RS256", headers: {})
    claims = {"iss" => provider.issuer, "aud" => provider.audience, "sub" => "NativeSubject", "nonce" => proof.fetch("nonce"),
              "iat" => Time.now.to_i, "exp" => Time.now.to_i + 300}.merge(attributes)
    claims.delete_if { |_, value| value == :absent }
    JWT.encode(claims, signing_key, algorithm, {kid: key_id}.merge(headers))
  end

  def complete(proof, jwt = token(proof), **attributes)
    post "/mobile/apple/session", params: {client_id: "ios", challenge_id: proof.fetch("challenge_id"),
                                           nonce: proof.fetch("nonce"), identity_token: jwt, **attributes}, as: :json
  end

  it "issues an expiring server nonce, accepts a verified native identity and leaves profile input untrusted" do
    proof = challenge
    expect(Session.count).to eq(0)
    expect(proof.keys).to contain_exactly("nonce", "challenge_id", "expires_at")
    complete(proof, token(proof, {"email" => "signed-claim@example.test", "email_verified" => true}), email: "attacker@example.test", name: "Untrusted")
    expect(response).to have_http_status(:created)
    expect(response.parsed_body.fetch("user_id")).to eq(user.id)
    expect(response.parsed_body.fetch("token")).to match(AddAuth::Core::MobileProfile::PATTERN)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(response.headers["Set-Cookie"]).to be_nil
    expect(user.reload.email_address).to eq("native-apple@example.test")
    expect(config.external_identities.providers).to be_empty
    expect(Session.last).to have_attributes(transport: "mobile", client_id: "ios", authenticated_with: "external_identity")
  end

  it "requires the correct issued challenge and nonce without burning a valid attempt" do
    proof = challenge
    valid = token(proof)
    [{challenge_id: "x" * 43}, {nonce: "y" * 43}, {client_id: "android"}, {nonce: nil}, {challenge_id: nil}].each do |attributes|
      complete(proof, valid, **attributes)
      expect(response).to have_http_status(:unauthorized)
      expect(AddAuthExternalTransaction.last.consumed_at).to be_nil
      expect(Session.count).to eq(0)
    end
    complete(proof, valid)
    expect(response).to have_http_status(:created)
    complete(proof, valid)
    expect(response).to have_http_status(:unauthorized)
    expect(Session.count).to eq(1)
  end

  {"wrong issuer" => {"iss" => "https://attacker.example.test"}, "wrong audience" => {"aud" => "web-client"},
   "missing expiry" => {"exp" => :absent}, "expired" => {"exp" => 1}, "missing nonce" => {"nonce" => :absent},
   "wrong nonce" => {"nonce" => "unissued"}, "blank subject" => {"sub" => ""},
   "future issued-at" => {"iat" => 9_999_999_999}, "pre-challenge token" => {"iat" => 1}}.each do |name, claims|
    it "rejects #{name} without creating a Session" do
      proof = challenge
      complete(proof, token(proof, claims))
      expect(response).to have_http_status(:unauthorized)
      expect(Session.count).to eq(0)
      expect(AddAuthExternalTransaction.last.consumed_at).to be_nil
    end
  end

  it "rejects algorithm substitution, signature substitution and token-selected key URLs" do
    proof = challenge
    [token(proof, {}, algorithm: "none", signing_key: nil), token(proof, {}, signing_key: OpenSSL::PKey::RSA.generate(2048)),
      token(proof, {}, signing_key: "attacker", algorithm: "HS256", headers: {jku: "http://127.0.0.1/private"})].each do |jwt|
      complete(proof, jwt)
      expect(response).to have_http_status(:unauthorized)
      expect(Session.count).to eq(0)
    end
    expect(WebMock).not_to have_requested(:get, "http://127.0.0.1/private")
  end

  it "refreshes the fixed JWKS once when the library cannot find a new key" do
    old_key = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048).public_key, kid: "old", alg: "RS256", use: "sig").export
    Rails.cache.write(AddAuth::Rails::ProviderLibraries::AppleJwks::CACHE_KEY, {"keys" => [old_key.transform_keys(&:to_s)]})
    proof = challenge
    complete(proof)
    expect(response).to have_http_status(:created)
    expect(WebMock).to have_requested(:get, "https://appleid.apple.com/auth/keys").once
  end

  it "reports a JWKS outage without consuming the challenge and permits retry after recovery" do
    stub_request(:get, "https://appleid.apple.com/auth/keys").to_timeout
    proof = challenge
    jwt = token(proof)
    complete(proof, jwt)
    expect(response).to have_http_status(:service_unavailable)
    expect(Session.count).to eq(0)
    expect(AddAuthExternalTransaction.last.consumed_at).to be_nil
    stub_request(:get, "https://appleid.apple.com/auth/keys").to_return(status: 200, body: jwks.to_json)
    complete(proof, jwt)
    expect(response).to have_http_status(:created)
  end

  it "refuses redirects, oversized or ambiguous JWKS instead of following an untrusted endpoint" do
    proof = challenge
    jwt = token(proof)
    [{status: 302, headers: {"Location" => "https://attacker.example.test/keys"}},
      {status: 200, body: "x" * 65_537}, {status: 200, body: {keys: jwks.fetch("keys") * 2}.to_json}].each do |response_stub|
      stub_request(:get, "https://appleid.apple.com/auth/keys").to_return(response_stub)
      complete(proof, jwt)
      expect(response).to have_http_status(:service_unavailable)
      expect(Session.count).to eq(0)
    end
    expect(WebMock).not_to have_requested(:get, "https://attacker.example.test/keys")
  end

  it "rejects a challenge after reset even with a subsequently verified Apple token" do
    proof = challenge
    user.update!(password: "replacement-password")
    complete(proof)
    expect(response).to have_http_status(:unauthorized)
    expect(Session.count).to eq(0)
  end

  it "cannot reinterpret a verified native result as another pending transaction" do
    proof = challenge
    runtime = AddAuth::Rails::Runtime
    pending = runtime.external_identities.pending(transaction: proof.fetch("challenge_id"), browser_secret: proof.fetch("nonce"), binding_context: "native:ios")
    result = AddAuth::Rails::ProviderLibraries::AppleNative::CallbackResult.capture(identity_token: token(proof), pending: pending,
      nonce: proof.fetch("nonce"), jwks: ->(_) { jwks })
    other_proof = challenge
    other = runtime.external_identities.pending(transaction: other_proof.fetch("challenge_id"), browser_secret: other_proof.fetch("nonce"), binding_context: "native:ios")
    expect(provider.verify(server_result: result, transaction: other)).to be_nil
    expect(provider.verify(server_result: {sub: "forged"}, transaction: pending)).to be_nil
  end

  it "binds the challenge to its registered client even when clients share a provider configuration" do
    config.mobile.apple_providers = {"ios" => provider.id, "android" => provider.id}
    proof = challenge
    jwt = token(proof)
    complete(proof, jwt, client_id: "android")
    expect(response).to have_http_status(:unauthorized)
    expect(Session.count).to eq(0)
    expect(AddAuthExternalTransaction.last.consumed_at).to be_nil
    complete(proof, jwt)
    expect(response).to have_http_status(:created)
    expect(Session.last.client_id).to eq("ios")
  end

  it "reports key cache failures without leaking backend details or consuming the challenge" do
    proof = challenge
    allow(Rails.cache).to receive(:read).with(AddAuth::Rails::ProviderLibraries::AppleJwks::CACHE_KEY).and_raise(IOError, "private-backend-detail")
    complete(proof)
    expect(response).to have_http_status(:service_unavailable)
    expect(response.body).not_to include("private-backend-detail")
    expect(AddAuthExternalTransaction.last.consumed_at).to be_nil
    expect(Session.count).to eq(0)
  end

  it "commits one session when a verified native challenge is exchanged concurrently" do
    proof = challenge
    jwt = token(proof)
    # Warm only the public key cache. Both requests still verify the signature
    # and compete to consume the same live transaction under the account lock.
    AddAuth::Rails::ProviderLibraries::AppleJwks.new(cache: Rails.cache).call
    ready, go = Queue.new, Queue.new
    operations = 2.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          go.pop
          AddAuth::Rails::Runtime.native_apple.complete(client_id: "ios", challenge_id: proof.fetch("challenge_id"),
            nonce: proof.fetch("nonce"), identity_token: jwt, ip: "127.0.0.1")
        end
      end
    end
    2.times { ready.pop }
    2.times { go << true }
    results = operations.map(&:value)
    expect(results.count(&:success?)).to eq(1)
    expect(Session.count).to eq(1)
    expect(AddAuthExternalTransaction.last.consumed_at).to be_present
  ensure
    operations&.each { |thread| thread.kill if thread.alive? }
  end
end
