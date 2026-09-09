# frozen_string_literal: true

require "rails_helper"

RSpec.describe AddAuth::AssetsController, type: :request do
  it "leaves Turbo absent when the host selects ordinary HTML navigation" do
    original = AddAuth.configuration.turbo_enabled
    AddAuth.configuration.turbo_enabled = false
    get "/add_auth/boot.js"
    expect(response.body).not_to include("turbo.js")
    expect(response.body).to include("challenge.js")
    get "/sign-in"
    expect(response.body).to include('data-turbo="false"')
  ensure
    AddAuth.configuration.turbo_enabled = original
  end

  it "serves public modules with forgery protection enabled and without a session" do
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    %w[boot turbo stimulus application codec passkey challenge].each do |asset|
      get "/add_auth/#{asset}.js"
      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("text/javascript")
      expect(response.body).to be_present
      expect(response.headers["Cross-Origin-Resource-Policy"]).to eq("same-origin")
      expect(response.headers["Set-Cookie"]).to be_nil
    end
    head "/add_auth/boot.js"
    expect(response).to have_http_status(:ok)
    expect(response.body).to be_empty
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  it "rejects unsafe methods even if a host routes them to an asset action" do
    %w[POST PATCH DELETE].each do |method|
      environment = Rack::MockRequest.env_for("/add_auth/boot.js", method: method)
      status, headers, body = described_class.action(:boot).call(environment)
      expect(status).to eq(405)
      expect(headers["allow"]).to eq("GET, HEAD")
      body.close if body.respond_to?(:close)
    end
  end
end
