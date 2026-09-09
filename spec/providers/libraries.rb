# frozen_string_literal: true

require "rails_helper"
require "rack/mock"
require "omniauth"
require "omniauth/google_oauth2"
require "omniauth/apple"
require "openid_connect"
require "add_auth/rails/provider_libraries/omniauth"
require "add_auth/rails/provider_libraries/openid_connect"
require "add_auth/rails/provider_libraries/apple_form_post_correlation"
require "add_auth/rails/provider_libraries/omniauth_correlation"
require "add_auth/rails/provider_libraries/request_protection"

RSpec.describe "provider-library callback boundaries" do
  let(:transaction) { Struct.new(:id).new("provider-transaction") }

  describe AddAuth::Rails::ProviderLibraries::RequestProtection do
    it "uses Rails tokens when the host has selected omniauth-rails_csrf_protection" do
      require "omniauth/rails_csrf_protection/token_verifier"
      previous = [OmniAuth.config.request_validation_phase, ActionController::Base.allow_forgery_protection]
      ActionController::Base.allow_forgery_protection = true
      phase = OmniAuth::RailsCsrfProtection::TokenVerifier.new
      OmniAuth.config.request_validation_phase = phase
      request = ActionDispatch::TestRequest.create
      request.set_header("rack.session", {})
      controller = ActionController::Base.new
      controller.set_request!(request)
      token = described_class.token(session: request.session, rails_token: -> { controller.send(:form_authenticity_token) })
      controller.commit_csrf_token(request)
      name = described_class.parameter
      env = Rack::MockRequest.env_for("/auth/google_oauth2", method: :post, params: {name => token})
      env["rack.session"] = request.session
      expect { phase.call(env) }.not_to raise_error
      forged = Rack::MockRequest.env_for("/auth/google_oauth2", method: :post, params: {name => "forged"})
      forged["rack.session"] = request.session
      expect { phase.call(forged) }.to raise_error(ActionController::InvalidAuthenticityToken)
      expect(OmniAuth.config.request_validation_phase).to equal(phase)
    ensure
      OmniAuth.config.request_validation_phase, ActionController::Base.allow_forgery_protection = previous if previous
    end

    it "uses the configured validator's session key without weakening CSRF" do
      previous = OmniAuth.config.request_validation_phase
      [:csrf, :_csrf_token].each do |key|
        phase = OmniAuth::AuthenticityTokenProtection.new(key: key, authenticity_param: "host_csrf")
        OmniAuth.config.request_validation_phase = phase
        session = {}
        token = described_class.token(session: session)
        expect(described_class.parameter).to eq("host_csrf")
        env = Rack::MockRequest.env_for("/auth/google_oauth2", method: :post, params: {"host_csrf" => token})
        env["rack.session"] = session
        expect { phase.call(env) }.not_to raise_error
        env = Rack::MockRequest.env_for("/auth/google_oauth2", method: :post, params: {"host_csrf" => "forged"})
        env["rack.session"] = session
        expect { phase.call(env) }.to raise_error(OmniAuth::AuthenticityError)
      end
      OmniAuth.config.request_validation_phase = ->(_env) {}
      expect { described_class.token(session: {}) }.to raise_error(AddAuth::Error)
    ensure
      OmniAuth.config.request_validation_phase = previous
    end
  end

  describe AddAuth::Rails::ProviderLibraries::OmniAuth::Verifier do
    it "accepts only the completed callback installed by actual OmniAuth middleware" do
      previous = [OmniAuth.config.test_mode, OmniAuth.config.mock_auth[:google_oauth2], OmniAuth.config.allowed_request_methods]
      OmniAuth.config.test_mode = true
      OmniAuth.config.allowed_request_methods = [:post]
      OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
        provider: "google_oauth2", uid: "google-subject",
        extra: {id_info: {iss: "https://accounts.google.com", aud: "google-client", sub: "google-subject", auth_time: 1_700_000_000}}
      )

      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "a" * 64
        use OmniAuth::Builder do
          provider :google_oauth2, "google-client", "google-secret"
        end
        run lambda { |env|
          if env["PATH_INFO"] == "/csrf"
            token = Rack::Protection::AuthenticityToken.token(env.fetch("rack.session"))
            next [200, {"content-type" => "text/plain"}, [token]]
          end
          callback = AddAuth::Rails::ProviderLibraries::OmniAuth::CallbackResult.capture(env: env, provider: :google_oauth2)
          verifier = AddAuth::Rails::ProviderLibraries::OmniAuth::Verifier.new(provider: :google_oauth2, provenance: "omniauth-google-oauth2")
          claims = verifier.call(server_result: callback, transaction: Struct.new(:id).new("transaction"))
          [claims ? 200 : 422, {"content-type" => "text/plain"}, [claims ? claims.fetch(:subject) : "rejected"]]
        }
      end
      request = Rack::MockRequest.new(app)

      # OmniAuth's request phase accepts POST only. A GET reaches the downstream
      # app rather than initiating a provider redirect.
      expect(request.get("/auth/google_oauth2")).not_to be_redirect
      csrf_failure = request.post("/auth/google_oauth2")
      expect(csrf_failure).to be_redirect
      expect(csrf_failure["Location"]).to include("/auth/failure")

      csrf = request.get("/csrf")
      cookie = csrf["Set-Cookie"].split(";", 2).first
      request_options = {params: {authenticity_token: csrf.body}}
      request_options["HTTP_COOKIE"] = cookie
      accepted = request.post("/auth/google_oauth2", request_options)
      expect(accepted).to be_redirect
      expect(accepted["Location"]).to include("/auth/google_oauth2/callback")
      expect(request.get("/auth/google_oauth2/callback").body).to eq("google-subject")
    ensure
      OmniAuth.config.test_mode, OmniAuth.config.mock_auth[:google_oauth2], OmniAuth.config.allowed_request_methods = previous if previous
    end

    it "rejects raw request data, a different strategy and incomplete mapped claims" do
      verifier = described_class.new(provider: :google_oauth2, provenance: "omniauth-google-oauth2")
      expect(verifier.call(server_result: {"uid" => "attacker"}, transaction: transaction)).to be_nil

      auth = OmniAuth::AuthHash.new(provider: "apple", uid: "subject", extra: {id_info: {iss: "issuer", aud: "client", sub: "subject"}})
      strategy = OmniAuth::Strategies::GoogleOauth2.new(->(_env) { [200, {}, []] }, "client", "secret")
      callback = AddAuth::Rails::ProviderLibraries::OmniAuth::CallbackResult.capture(env: {"omniauth.strategy" => strategy, "omniauth.auth" => auth}, provider: :google_oauth2)
      expect(callback).to be_nil
    end

    it "returns only mapped identity claims and never exposes provider credentials or profiles" do
      auth = OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "subject",
        credentials: {token: "never-store-this"}, extra: {id_info: {iss: "issuer", aud: "client", sub: "subject", auth_time: 1_700_000_000}})
      strategy = OmniAuth::Strategies::GoogleOauth2.new(->(_env) { [200, {}, []] }, "client", "secret")
      callback = AddAuth::Rails::ProviderLibraries::OmniAuth::CallbackResult.capture(env: {"omniauth.strategy" => strategy, "omniauth.auth" => auth}, provider: :google_oauth2)
      claims = described_class.new(provider: :google_oauth2, provenance: "omniauth-google-oauth2").call(server_result: callback, transaction: transaction)

      expect(claims).to eq(issuer: "issuer", audience: "client", subject: "subject", provenance: "omniauth-google-oauth2",
        authenticated_at: Time.at(1_700_000_000).utc)
      expect(callback).not_to respond_to(:auth)
      expect(callback.inspect).to include("FILTERED")
    end

    it "fails closed for a malformed provider authentication occurrence time" do
      auth = OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "subject",
        extra: {id_info: {iss: "issuer", aud: "client", sub: "subject", auth_time: Float::NAN}})
      strategy = OmniAuth::Strategies::GoogleOauth2.new(->(_env) { [200, {}, []] }, "client", "secret")
      callback = AddAuth::Rails::ProviderLibraries::OmniAuth::CallbackResult.capture(env: {"omniauth.strategy" => strategy, "omniauth.auth" => auth}, provider: :google_oauth2)

      expect(described_class.new(provider: :google_oauth2, provenance: "omniauth-google-oauth2").call(server_result: callback, transaction: transaction)).to be_nil
    end
  end

  describe AddAuth::Rails::ProviderLibraries::OpenIdConnect::CallbackResult do
    it "uses openid_connect's signed-token verification after a server code exchange" do
      signing_key = OpenSSL::PKey::RSA.generate(2048)
      id_token = OpenIDConnect::ResponseObject::IdToken.new(iss: "https://login.example.test", sub: "oidc-subject",
        aud: "oidc-client", exp: Time.now.to_i + 60, iat: Time.now.to_i, nonce: "bound-nonce", auth_time: Time.now.to_i - 10)
      client = OpenIDConnect::Client.new(identifier: "oidc-client", secret: "secret", redirect_uri: "https://app.example.test/callback")
      response = OpenIDConnect::AccessToken.new(access_token: "provider-access-token", id_token: id_token.to_jwt(signing_key), client: client)

      result = described_class.capture(access_token: response, verification_key: signing_key.public_key,
        issuer: "https://login.example.test", audience: "oidc-client", nonce: "bound-nonce", provenance: "openid_connect")

      expect(result.to_verified_claims(transaction: transaction)).to include(issuer: "https://login.example.test",
        audience: "oidc-client", subject: "oidc-subject", provenance: "openid_connect")
      expect(result.inspect).to include("FILTERED")
    end

    it "rejects an invalid signature, claim mismatch and a non-library token response" do
      signing_key = OpenSSL::PKey::RSA.generate(2048)
      id_token = OpenIDConnect::ResponseObject::IdToken.new(iss: "https://login.example.test", sub: "oidc-subject",
        aud: "oidc-client", exp: Time.now.to_i + 60, iat: Time.now.to_i, nonce: "bound-nonce")
      client = OpenIDConnect::Client.new(identifier: "oidc-client", secret: "secret", redirect_uri: "https://app.example.test/callback")
      response = OpenIDConnect::AccessToken.new(access_token: "provider-access-token", id_token: id_token.to_jwt(signing_key), client: client)

      expect(described_class.capture(access_token: response, verification_key: OpenSSL::PKey::RSA.generate(2048).public_key,
        issuer: "https://login.example.test", audience: "oidc-client", nonce: "bound-nonce", provenance: "openid_connect")).to be_nil
      expect(described_class.capture(access_token: response, verification_key: signing_key.public_key,
        issuer: "https://login.example.test", audience: "wrong-client", nonce: "bound-nonce", provenance: "openid_connect")).to be_nil
      expect(described_class.capture(access_token: Struct.new(:id_token).new(response.id_token), verification_key: signing_key.public_key,
        issuer: "https://login.example.test", audience: "oidc-client", nonce: "bound-nonce", provenance: "openid_connect")).to be_nil
    end
  end

  describe AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation do
    it "captures state and nonce from the actual Apple middleware request phase" do
      key = "k" * 32
      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "s" * 64
        use AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation, key: key
        use OmniAuth::Builder do
          provider :apple, "apple-client", "", team_id: "team-id", key_id: "key-id", pem: OpenSSL::PKey::EC.generate("prime256v1").to_pem
        end
        run lambda { |env|
          AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation.remember!(session: env.fetch("rack.session"),
            transaction: "transaction", browser_secret: "browser-secret", configuration_id: "apple", purpose: :sign_in)
          token = Rack::Protection::AuthenticityToken.token(env.fetch("rack.session"))
          [200, {"content-type" => "text/plain"}, [token]]
        }
      end
      request = Rack::MockRequest.new(app)

      prepared = request.get("/prepare")
      normal_cookie = prepared["Set-Cookie"].split(";", 2).first
      options = {params: {authenticity_token: prepared.body}}
      options["HTTP_COOKIE"] = normal_cookie
      started = request.post("/auth/apple", options)
      callback_cookie = Array(started["Set-Cookie"]).find { |line| line.start_with?("add_auth_apple_callback=") }

      expect(started).to be_redirect
      expect(started["Location"]).to start_with("https://appleid.apple.com/auth/authorize")
      expect(callback_cookie).to include("path=/auth/apple/callback", "samesite=none")
    end

    it "uses a callback-scoped SameSite=None cookie without changing the ordinary session" do
      key = "k" * 32
      observed = nil
      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "s" * 64
        use AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation, key: key
        run lambda { |env|
          case env["PATH_INFO"]
          when "/prepare"
            AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation.remember!(session: env.fetch("rack.session"),
              transaction: "transaction", browser_secret: "browser-secret", configuration_id: "apple", purpose: :sign_in)
            [200, {"content-type" => "text/plain"}, ["prepared"]]
          when "/auth/apple"
            env.fetch("rack.session")["omniauth.state"] = "state"
            env.fetch("rack.session")["omniauth.nonce"] = "nonce"
            [303, {"location" => "https://appleid.apple.com/auth/authorize"}, []]
          when "/auth/apple/callback"
            observed = [env.fetch("rack.session")["omniauth.state"], env.fetch("rack.session")["omniauth.nonce"],
              env.fetch("add_auth.apple_correlation")]
            [200, {"content-type" => "text/plain"}, ["completed"]]
          else
            [404, {}, []]
          end
        }
      end
      request = Rack::MockRequest.new(app)

      prepared = request.get("/prepare")
      normal_cookie = prepared["Set-Cookie"].split(";", 2).first
      started = request.post("/auth/apple", "HTTP_COOKIE" => normal_cookie)
      callback_cookie = Array(started["Set-Cookie"]).find { |line| line.start_with?("add_auth_apple_callback=") }

      expect(callback_cookie).to include("path=/auth/apple/callback", "secure", "httponly", "samesite=none")
      callback = request.post("/auth/apple/callback", "HTTP_COOKIE" => callback_cookie.split(";", 2).first)
      expect(callback.status).to eq(200)
      expect(observed).to eq(["state", "nonce", {"transaction" => "transaction", "browser_secret" => "browser-secret", "configuration_id" => "apple", "purpose" => "sign_in", "remember" => false}])
      expect(Array(callback["Set-Cookie"]).join("\n")).to include("add_auth_apple_callback=", "max-age=0")
    end

    it "leaves host-owned provider requests and missing-capsule callbacks untouched" do
      observed = []
      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "s" * 64
        use AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation, key: "k" * 32
        run lambda { |env|
          observed << env["add_auth.apple_correlation"]
          [302, {"location" => "/host-owned"}, ["host result"]]
        }
      end

      request = Rack::MockRequest.new(app)
      [request.post("/auth/apple"), request.post("/auth/apple/callback")].each do |response|
        expect(response.status).to eq(302)
        expect(response["location"]).to eq("/host-owned")
        expect(response.body).to eq("host result")
      end
      expect(observed).to eq([nil, nil])
    end

    it "fails closed for a modified AddAuth callback cookie" do
      calls = 0
      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "s" * 64
        use AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation, key: "k" * 32
        run lambda { |_env|
          calls += 1
          [200, {}, []]
        }
      end
      request = Rack::MockRequest.new(app)

      modified = request.post("/auth/apple/callback", "HTTP_COOKIE" => "add_auth_apple_callback=not-a-valid-cookie")

      expect(modified.status).to eq(422)
      expect(calls).to eq(0)
    end
  end

  describe AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation do
    it "preserves real host-owned OAuth initiation, CSRF and custom failure routing" do
      previous = [OmniAuth.config.test_mode, OmniAuth.config.request_validation_phase, OmniAuth.config.on_failure]
      OmniAuth.config.test_mode = false
      validator = OmniAuth::AuthenticityTokenProtection.new(key: :host_oauth_csrf)
      OmniAuth.config.request_validation_phase = validator
      failure_handler = ->(_env) { [303, {"location" => "/host/oauth-failed", "x-host-handler" => "retained"}, ["host failure"]] }
      OmniAuth.config.on_failure = failure_handler
      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "s" * 64
        use AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation, providers: ["google_oauth2"]
        use OmniAuth::Builder do
          provider :google_oauth2, "host-client", "host-secret", scope: "email,profile"
        end
        run lambda { |env|
          [200, {"content-type" => "text/plain"}, [validator.mask_authenticity_token(env.fetch("rack.session"))]]
        }
      end
      request = Rack::MockRequest.new(app)
      prepared = request.get("/host/csrf")
      cookie = prepared["Set-Cookie"].split(";", 2).first
      started = request.post("/auth/google_oauth2", "HTTP_COOKIE" => cookie, :params => {authenticity_token: prepared.body})
      expect(started.status).to eq(302)
      authorization = Rack::Utils.parse_query(URI(started["location"]).query)
      expect(authorization).to include("client_id" => "host-client", "scope" => "email profile")
      expect(authorization["state"]).not_to be_empty

      forged = request.post("/auth/google_oauth2", "HTTP_COOKIE" => cookie, :params => {authenticity_token: "forged"})
      callback = request.get("/auth/google_oauth2/callback?state=wrong&code=forged", "HTTP_COOKIE" => cookie)
      [forged, callback].each do |response|
        expect(response.status).to eq(303)
        expect(response["location"]).to eq("/host/oauth-failed")
        expect(response["x-host-handler"]).to eq("retained")
        expect(response.body).to eq("host failure")
      end
      expect(OmniAuth.config.request_validation_phase).to equal(validator)
      expect(OmniAuth.config.on_failure).to equal(failure_handler)
      expect(OmniAuth.config.test_mode).to be(false)
    ensure
      OmniAuth.config.test_mode, OmniAuth.config.request_validation_phase, OmniAuth.config.on_failure = previous if previous
    end

    it "preserves library failures for AddAuth-owned initiation" do
      response = [401, {"content-type" => "text/plain", "x-host-handler" => "retained"}, ["provider refused"]]
      pending_session = {}
      described_class.remember!(session: pending_session, provider: "google_oauth2", transaction: "transaction",
        browser_secret: "browser", configuration_id: "google", purpose: :sign_in)
      app = described_class.new(->(_env) { response }, providers: ["google_oauth2"])
      env = Rack::MockRequest.env_for("/auth/google_oauth2", method: :post)
      env["rack.session"] = pending_session
      expect(app.call(env)).to eq(response)
      expect(pending_session[described_class::CORRELATIONS_KEY]).to be_nil
    end

    it "leaves unrelated routes and host-owned callbacks unchanged with no AddAuth evidence" do
      observed = []
      response = [202, {"x-host-handler" => "retained"}, ["host callback"]]
      app = described_class.new(lambda { |env|
        observed << env[described_class::ENV_KEY]
        response
      }, providers: ["google_oauth2"])
      request = Rack::MockRequest.new(app)
      ["/auth/google_oauth2/callback?state=host-state", "/auth/github/callback?code=host-code", "/host/custom-oauth"].each do |path|
        result = request.get(path)
        expect(result.status).to eq(202)
        expect(result.body).to eq("host callback")
        expect(result["x-host-handler"]).to eq("retained")
      end
      expect(observed).to eq([nil, nil, nil])
    end

    it "binds each normal callback to OmniAuth state without exposing a raw callback parameter" do
      observed = nil
      app = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "s" * 64
        use AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation, providers: ["google_oauth2"]
        run lambda { |env|
          case env["PATH_INFO"]
          when "/prepare"
            AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation.remember!(session: env.fetch("rack.session"), provider: "google_oauth2",
              transaction: "transaction", browser_secret: "browser-secret", configuration_id: "google", purpose: :sign_in, remember: true)
            [200, {"content-type" => "text/plain"}, ["prepared"]]
          when "/auth/google_oauth2"
            env.fetch("rack.session")["omniauth.state"] = "provider-state"
            [303, {"location" => "https://accounts.example.test/authorize"}, []]
          when "/auth/google_oauth2/callback"
            observed = env["add_auth.provider_correlation"]
            next [422, {}, []] unless observed
            [200, {"content-type" => "text/plain"}, ["completed"]]
          else
            [404, {}, []]
          end
        }
      end
      request = Rack::MockRequest.new(app)

      prepared = request.get("/prepare")
      cookie = prepared["Set-Cookie"].split(";", 2).first
      started = request.post("/auth/google_oauth2", "HTTP_COOKIE" => cookie)
      callback_cookie = started["Set-Cookie"].split(";", 2).first
      response = request.get("/auth/google_oauth2/callback?state=provider-state", "HTTP_COOKIE" => callback_cookie)

      expect(started).to be_redirect
      expect(response.status).to eq(200)
      expect(observed).to eq({"transaction" => "transaction", "browser_secret" => "browser-secret",
        "configuration_id" => "google", "purpose" => "sign_in", "remember" => true})
      consumed_cookie = response["Set-Cookie"].split(";", 2).first
      expect(request.get("/auth/google_oauth2/callback?state=provider-state", "HTTP_COOKIE" => consumed_cookie).status).to eq(422)
    end
  end
end
