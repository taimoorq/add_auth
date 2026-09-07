# frozen_string_literal: true

require "rails_helper"

RSpec.describe Latchkey::AssetsController, type: :request do
  it "serves public modules with forgery protection enabled and without a session" do
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    %w[boot turbo stimulus application codec passkey challenge].each do |asset|
      get "/latchkey/#{asset}.js"
      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("text/javascript")
      expect(response.body).to be_present
      expect(response.headers["Cross-Origin-Resource-Policy"]).to eq("same-origin")
      expect(response.headers["Set-Cookie"]).to be_nil
    end
    head "/latchkey/boot.js"
    expect(response).to have_http_status(:ok)
    expect(response.body).to be_empty
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  it "rejects unsafe methods even if a host routes them to an asset action" do
    %w[POST PATCH DELETE].each do |method|
      environment = Rack::MockRequest.env_for("/latchkey/boot.js", method: method)
      status, headers, body = described_class.action(:boot).call(environment)
      expect(status).to eq(405)
      expect(headers["allow"]).to eq("GET, HEAD")
      body.close if body.respond_to?(:close)
    end
  end
end
