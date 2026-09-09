# frozen_string_literal: true

# Loaded only by the disposable HTTPS host, never by production configuration.
require "json"
require "cgi"
require "openssl"
require "omniauth-apple"
require "webmock"
require "add_auth/rails/provider_libraries/apple_form_post_correlation"
require "add_auth/rails/provider_libraries/omniauth"

module AppleFormPostServer
  extend self

  CLIENT = "fixture-apple-client"
  SUBJECT = "fixture-apple-subject"
  SESSION_COOKIE = "_apple_https_fixture"
  CAPSULE_COOKIE = AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation::COOKIE

  def configure(app)
    @mutex = Mutex.new
    @tokens, @callbacks, @exchanges = {}, [], []
    @mode = "valid"
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @other_rsa = OpenSSL::PKey::RSA.generate(2048)
    @client_key = OpenSSL::PKey::EC.generate("prime256v1")
    @jwk = JSON::JWK.new(@rsa.public_key, kid: "fixture-apple-key", use: "sig", alg: "RS256")
    @keys_reads = 0
    WebMock.enable!
    WebMock.disable_net_connect!(allow_localhost: true)
    WebMock.stub_request(:get, "https://appleid.apple.com/auth/keys").to_return do
      @mutex.synchronize { @keys_reads += 1 }
      {status: 200, headers: {"Content-Type" => "application/json"}, body: JSON.generate(keys: [@jwk])}
    end
    WebMock.stub_request(:post, "https://appleid.apple.com/auth/token").to_return do |request|
      fields = URI.decode_www_form(request.body).to_h
      token = @mutex.synchronize do
        @exchanges << {"grant_type" => fields["grant_type"], "client_id" => fields["client_id"], "redirect_uri" => fields["redirect_uri"]}
        @tokens.fetch(fields.fetch("code"))
      end
      {status: 200, headers: {"Content-Type" => "application/json"}, body: JSON.generate(access_token: "synthetic-unused-access-token", token_type: "bearer", expires_in: 3600, id_token: token)}
    end

    app.config.hosts.clear
    app.config.action_controller.allow_forgery_protection = true
    app.config.session_store :cookie_store, key: SESSION_COOKIE, same_site: :lax, secure: true, httponly: true
    app.config.middleware.insert_before ActionDispatch::Cookies, Audit
    app.config.middleware.use AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation,
      key: app.key_generator.generate_key("add_auth.apple-form-post.v1", 32)
    app.config.middleware.use OmniAuth::Builder do
      provider :apple, CLIENT, "unused", team_id: "fixture-team", key_id: "fixture-client-key",
        pem: AppleFormPostServer.client_pem,
        redirect_uri: "#{AppleFormPostServer.origin}/auth/apple/callback",
        client_options: {authorize_url: "#{AppleFormPostServer.idp_origin}/authorize"}
    end
    OmniAuth.config.test_mode = false
    OmniAuth.config.allowed_request_methods = [:post]
    OmniAuth.config.on_failure = ->(_env) { [422, {"content-type" => "text/plain"}, ["Apple strategy rejected callback"]] }
    verifier = AddAuth::Rails::ProviderLibraries::OmniAuth::Verifier.new(provider: "apple", provenance: "omniauth-apple-1.4.0",
      mapping: {issuer: %i[extra raw_info id_info iss], audience: %i[extra raw_info id_info aud],
                subject: %i[extra raw_info id_info sub], authenticated_at: %i[extra raw_info id_info auth_time]})
    @configuration = AddAuth::Core::ExternalIdentities::Configuration.new(id: "apple", issuer: "https://appleid.apple.com", audience: CLIENT, verifier: verifier)
    AddAuth.configure do |config|
      config.base_url = origin
      config.external_identities.register(id: "apple", label: "Apple", middleware_name: "apple", configuration: @configuration, apple_form_post: true)
      config.external_identities.enabled = true
      config.mobile.enabled = true
      config.mobile.lifetime = 30 * 86_400
      config.mobile.idle_timeout = 14 * 86_400
      config.mobile.clients = ["android"]
      config.mobile.callbacks = {"android" => "https://localhost:#{ENV.fetch("MOBILE_CALLBACK_PORT")}/callback"}
    end
  end

  def client_pem = @client_key.to_pem
  def origin = "https://localhost:#{ENV.fetch("APPLE_HTTPS_PORT")}"
  def idp_origin = "http://127.0.0.1:#{ENV.fetch("APPLE_IDP_PORT")}"

  def seed!
    user = User.create!(email_address: "apple-owner@example.test", password: "fixture-password")
    AddAuthExternalIdentity.create!(user: user, namespace: @configuration.namespace(SUBJECT), provider_id: "apple",
      issuer: @configuration.issuer, audience: CLIENT, subject: SUBJECT, provenance: "fixture-existing-binding",
      credential_version: SecureRandom.hex(16), linked_at: Time.now - 60)
  end

  def audit(env, status)
    @mutex.synchronize do
      @callbacks << {"cookies" => Rack::Utils.parse_cookies_header(env["HTTP_COOKIE"]).keys,
                     "fetch_site" => env["HTTP_SEC_FETCH_SITE"], "method" => env["REQUEST_METHOD"], "status" => status,
                     "strategy" => env["omniauth.strategy"]&.class&.name,
                     "verified_uid" => env["omniauth.auth"]&.uid}
    end
  end

  class Audit
    def initialize(app) = @app = app

    def call(env)
      result = @app.call(env)
      AppleFormPostServer.audit(env, result[0]) if env["PATH_INFO"] == "/auth/apple/callback"
      result
    end
  end

  def idp(env)
    request = Rack::Request.new(env)
    case request.path_info
    when "/reset"
      AddAuth.configuration.turbo_enabled = request.params.fetch("browser_mode", "turbo") == "turbo"
      ActiveRecord::Base.connection_pool.with_connection do
        Session.delete_all
        AddAuthMobileHandoff.delete_all
        AddAuthExternalTransaction.delete_all
      end
      @mutex.synchronize {
        @mode = request.params.fetch("mode")
        @tokens.clear
        @callbacks.clear
        @exchanges.clear
      }
      [200, {"content-type" => "text/plain"}, ["reset"]]
    when "/status"
      values = @mutex.synchronize {
        {callbacks: @callbacks.dup, exchanges: @exchanges.dup, keys_reads: @keys_reads,
         strategy_version: Gem.loaded_specs.fetch("omniauth-apple").version.to_s}
      }
      ActiveRecord::Base.connection_pool.with_connection do
        values[:sessions] = Session.where(revoked_at: nil).pluck(:authenticated_with)
        values[:consumed] = AddAuthExternalTransaction.where.not(consumed_at: nil).count
      end
      [200, {"content-type" => "application/json"}, [JSON.generate(values)]]
    when "/authorize"
      params = request.params
      raise "Apple request must require form_post" unless params.fetch("response_mode") == "form_post"
      mode = @mutex.synchronize { @mode }
      now = Time.now.to_i
      claims = {iss: "https://appleid.apple.com", aud: CLIENT, sub: SUBJECT, iat: now - 1, exp: now + 300,
                nonce_supported: true, nonce: params.fetch("nonce")}
      changes = {"nonce" => {nonce: "mismatched-nonce"}, "issuer" => {iss: "https://untrusted.example.test"},
                 "audience" => {aud: "different-client"}, "issued_at" => {iat: now + 3600}, "expired" => {exp: now - 60}}
      claims.merge!(changes.fetch(mode, {}))
      jwt = JSON::JWT.new(claims)
      jwt.kid = "fixture-apple-key"
      encoded = jwt.sign((mode == "signature") ? @other_rsa : @rsa, :RS256).to_s
      code = SecureRandom.hex(16)
      state = (mode == "state") ? "mismatched-state" : params.fetch("state")
      @mutex.synchronize { @tokens[code] = encoded }
      body = <<~HTML
        <!doctype html><html><body><h1>Local Apple identity provider</h1>
        <form method="post" action="#{CGI.escapeHTML(params.fetch("redirect_uri"))}">
          <input type="hidden" name="code" value="#{code}">
          <input type="hidden" name="state" value="#{CGI.escapeHTML(state)}">
          <button type="submit">Return from Apple</button>
        </form></body></html>
      HTML
      [200, {"content-type" => "text/html"}, [body]]
    else
      [404, {"content-type" => "text/plain"}, ["not found"]]
    end
  end
end
