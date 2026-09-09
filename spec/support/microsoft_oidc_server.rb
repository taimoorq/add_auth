# frozen_string_literal: true

# Host-owned configuration and a real local IdP, confined to a disposable app.
require "json"
require "cgi"
require "openssl"
require "omniauth_openid_connect"
require "add_auth/rails/provider_libraries/omniauth"
require "add_auth/rails/provider_libraries/omniauth_correlation"

module MicrosoftOidcServer
  extend self

  TENANT = "11111111-2222-3333-4444-555555555555"
  ISSUER = "https://login.microsoftonline.com/#{TENANT}/v2.0"
  CLIENT = "fixture-microsoft-client"
  SUBJECT = "fixture-microsoft-pairwise-subject"
  USER_ID = "ac782247-7da0-4c52-903f-234fcc409640"
  COOKIE = "_microsoft_browser_fixture"
  SCOPES = %w[openid profile email].freeze

  def configure(app)
    @mutex = Mutex.new
    @codes, @callbacks, @exchanges, @requests = {}, [], [], []
    @mode = "valid"
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @wrong_key = OpenSSL::PKey::RSA.generate(2048)
    @jwk = JSON::JWK.new(@rsa.public_key, kid: "microsoft-fixture-key", use: "sig", alg: "RS256")
    @key_reads, @userinfo_reads = 0, 0
    # Never assign OmniAuth global settings, request validator, scopes, or failure
    # handler on behalf of AddAuth. These defaults remain owned by this host.
    @failure_handler = OmniAuth.config.on_failure
    @validator = OmniAuth.config.request_validation_phase
    @allowed_methods = OmniAuth.config.allowed_request_methods.dup
    raise "Real OmniAuth middleware is required" if OmniAuth.config.test_mode
    app.config.hosts.clear
    app.config.action_controller.allow_forgery_protection = true
    app.config.action_dispatch.show_exceptions = :all
    app.config.session_store :cookie_store, key: COOKIE, same_site: :lax, httponly: true
    app.config.middleware.insert_before ActionDispatch::ShowExceptions, Audit
    app.config.middleware.use AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation, providers: ["microsoft"]
    app.config.middleware.use OmniAuth::Builder do
      provider :openid_connect, name: :microsoft, issuer: ISSUER, discovery: false,
        scope: SCOPES.map(&:to_sym), response_type: :code, client_signing_alg: :RS256,
        client_auth_method: :basic, send_nonce: true, require_state: true,
        client_options: {identifier: CLIENT, secret: "synthetic-client-secret", scheme: "http",
                         host: "127.0.0.1", port: ENV.fetch("MICROSOFT_IDP_PORT").to_i,
                         redirect_uri: "#{MicrosoftOidcServer.origin}/auth/microsoft/callback",
                         authorization_endpoint: "/#{TENANT}/oauth2/v2.0/authorize",
                         token_endpoint: "/#{TENANT}/oauth2/v2.0/token",
                         userinfo_endpoint: "/oidc/userinfo", jwks_uri: "#{MicrosoftOidcServer.idp_origin}/#{TENANT}/discovery/v2.0/keys"}
    end
    verifier = AddAuth::Rails::ProviderLibraries::OmniAuth::Verifier.new(provider: "microsoft", provenance: "omniauth_openid_connect-0.8.0",
      mapping: {issuer: %i[extra raw_info iss], audience: %i[extra raw_info aud], subject: %i[extra raw_info sub],
                authenticated_at: %i[extra raw_info auth_time]})
    @configuration = AddAuth::Core::ExternalIdentities::Configuration.new(id: "microsoft", issuer: ISSUER, audience: CLIENT, verifier: verifier)
    AddAuth.configure do |config|
      config.base_url = origin
      config.turbo_enabled = false
      config.external_identities.register(id: "microsoft", label: "Microsoft", middleware_name: "microsoft", configuration: @configuration)
      config.external_identities.enabled = true
      config.mobile.enabled = true
      config.mobile.lifetime = 30 * 86_400
      config.mobile.idle_timeout = 14 * 86_400
      config.mobile.clients = ["android"]
      config.mobile.callbacks = {"android" => "https://localhost:#{ENV.fetch("MOBILE_CALLBACK_PORT")}/callback"}
    end
  end

  def origin = "http://localhost:#{ENV.fetch("MICROSOFT_APP_PORT")}"
  def idp_origin = "http://127.0.0.1:#{ENV.fetch("MICROSOFT_IDP_PORT")}"

  def seed!
    raise "Native UUID schema required" unless User.columns_hash.fetch("id").type == :uuid
    user = User.create!(id: USER_ID, email_address: "original-owner@example.test", password: "fixture-password")
    User.create!(email_address: "profile-drift@example.test", password: "another-password")
    AddAuthExternalIdentity.create!(user: user, namespace: @configuration.namespace(SUBJECT), provider_id: "microsoft", issuer: ISSUER,
      audience: CLIENT, subject: SUBJECT, provenance: "fixture-existing-binding", credential_version: SecureRandom.hex(16), linked_at: Time.now - 60)
  end

  def audit(env, status)
    @mutex.synchronize do
      @callbacks << {"status" => status, "method" => env["REQUEST_METHOD"], "fetch_site" => env["HTTP_SEC_FETCH_SITE"],
                     "strategy" => env["omniauth.strategy"]&.class&.name, "verified_uid" => env["omniauth.auth"]&.uid,
                     "exception" => env["action_dispatch.exception"]&.class&.name,
                     "omniauth_error" => env["omniauth.error"]&.class&.name,
                     "cookies" => Rack::Utils.parse_cookies_header(env["HTTP_COOKIE"]).keys}
    end
  end

  class Audit
    def initialize(app) = @app = app

    def call(env)
      result = @app.call(env)
      MicrosoftOidcServer.audit(env, result[0]) if env["PATH_INFO"] == "/auth/microsoft/callback"
      result
    end
  end

  def idp(env)
    request = Rack::Request.new(env)
    case request.path_info
    when "/reset"
      AddAuth.configuration.turbo_enabled = request.params["turbo"] == "true"
      ActiveRecord::Base.connection_pool.with_connection do
        Session.delete_all
        AddAuthMobileHandoff.delete_all
        AddAuthExternalTransaction.delete_all
      end
      @mutex.synchronize do
        @mode = request.params.fetch("mode")
        @codes.clear
        @callbacks.clear
        @exchanges.clear
        @requests.clear
        @key_reads = @userinfo_reads = 0
      end
      json(reset: true)
    when "/status" then status
    when "/#{TENANT}/oauth2/v2.0/authorize" then authorize(request)
    when "/#{TENANT}/oauth2/v2.0/token" then token(request)
    when "/#{TENANT}/discovery/v2.0/keys"
      @mutex.synchronize { @key_reads += 1 }
      json(keys: [@jwk])
    when "/oidc/userinfo"
      return json({error: "invalid_token"}, status: 401) unless request.get_header("HTTP_AUTHORIZATION") == "Bearer synthetic-access-token"
      @mutex.synchronize { @userinfo_reads += 1 }
      json(sub: SUBJECT, email: "profile-drift@example.test", preferred_username: "profile-drift@example.test", name: "Untrusted profile name")
    else
      [404, {"content-type" => "text/plain"}, ["not found"]]
    end
  end

  def authorize(request)
    params = request.params
    raise "Unexpected client or response type" unless params.fetch("client_id") == CLIENT && params.fetch("response_type") == "code"
    raise "Host scopes changed" unless params.fetch("scope").split.sort == SCOPES.sort
    mode = @mutex.synchronize { @mode }
    now = Time.now.to_i
    claims = {iss: ISSUER, aud: CLIENT, sub: SUBJECT, iat: now - 1, exp: now + 300, nonce: params.fetch("nonce")}
    claims.merge!({"nonce" => {nonce: "other-browser-nonce"}, "issuer" => {iss: "https://login.microsoftonline.com/other-tenant/v2.0"},
                   "audience" => {aud: "different-client"}, "expired" => {exp: now - 60}}.fetch(mode, {}))
    jwt = JSON::JWT.new(claims)
    jwt.kid = "microsoft-fixture-key"
    signed = jwt.sign((mode == "signature") ? @wrong_key : @rsa, :RS256).to_s
    code = SecureRandom.hex(16)
    state = (mode == "state") ? "mismatched-state" : params.fetch("state")
    callback = params.fetch("redirect_uri") + "?" + URI.encode_www_form(code: code, state: state)
    @mutex.synchronize do
      @codes[code] = signed
      @requests << {"client" => params["client_id"], "scope" => params["scope"], "response_type" => params["response_type"], "nonce_present" => !params["nonce"].to_s.empty?}
    end
    [200, {"content-type" => "text/html"}, [<<~HTML]]
      <!doctype html><html><body><h1>Local Microsoft identity provider</h1>
      <a id="microsoft-return" href="#{CGI.escapeHTML(callback)}">Return from Microsoft</a>
      </body></html>
    HTML
  end

  def token(request)
    raise "Token exchange must use POST" unless request.post?
    client = Rack::Auth::Basic::Request.new(request.env)
    return json({error: "invalid_client"}, status: 401) unless client.provided? && client.credentials == [CLIENT, "synthetic-client-secret"]
    params = request.params
    signed = @mutex.synchronize do
      @exchanges << {"client" => client.credentials.first, "grant_type" => params["grant_type"], "redirect_uri" => params["redirect_uri"]}
      @codes.delete(params["code"])
    end
    return json({error: "invalid_grant"}, status: 400) unless signed && params["grant_type"] == "authorization_code" && params["redirect_uri"] == "#{origin}/auth/microsoft/callback"
    json(access_token: "synthetic-access-token", token_type: "Bearer", expires_in: 3600, id_token: signed)
  end

  def status
    result = @mutex.synchronize do
      {callbacks: @callbacks.dup, exchanges: @exchanges.dup, requests: @requests.dup, key_reads: @key_reads, userinfo_reads: @userinfo_reads,
       strategy_version: Gem.loaded_specs.fetch("omniauth_openid_connect").version.to_s,
       failure_handler_unchanged: OmniAuth.config.on_failure.equal?(@failure_handler), validator_unchanged: OmniAuth.config.request_validation_phase.equal?(@validator),
       methods_unchanged: OmniAuth.config.allowed_request_methods == @allowed_methods, turbo: AddAuth.configuration.turbo_enabled}
    end
    ActiveRecord::Base.connection_pool.with_connection do
      result[:sessions] = Session.where(revoked_at: nil).pluck(:user_id, :authenticated_with)
      result[:consumed] = AddAuthExternalTransaction.where.not(consumed_at: nil).count
      result[:user_type] = User.columns_hash.fetch("id").type.to_s
      result[:owner_email] = User.find(USER_ID).email_address
      result[:identity_owner] = AddAuthExternalIdentity.first.user_id
      result[:users_count] = User.count
    end
    json(result)
  end

  def json(values = nil, status: 200, **fields)
    [status, {"content-type" => "application/json"}, [JSON.generate(values || fields)]]
  end
end
