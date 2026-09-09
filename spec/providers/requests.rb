# frozen_string_literal: true

require "rails_helper"
require "omniauth"
require "add_auth/core/challenge/test"

RSpec.describe "Provider sign-in preparation", type: :request do
  before { AddAuth.configuration.rate_limit_store.clear }

  let(:configuration) do
    AddAuth::Core::ExternalIdentities::Configuration.new(id: "google", issuer: "https://accounts.google.com",
      audience: "browser-client", verifier: ->(**) {})
  end
  let(:pending) { Struct.new(:id, :purpose, :configuration).new("opaque-transaction", :sign_in, configuration) }
  let(:result) { double(success?: true, credential: pending) }
  let(:service) { double(begin_transaction: result) }

  around do |example|
    options = AddAuth::Configuration::ExternalIdentityOptions.new
    options.register(id: "google", label: "Google", middleware_name: "google_oauth2", configuration: configuration)
    options.enabled = true
    previous = AddAuth.configuration.external_identities
    AddAuth.configuration.instance_variable_set(:@external_identities, options)
    example.run
  ensure
    AddAuth.configuration.instance_variable_set(:@external_identities, previous)
  end

  before do
    allow(AddAuth::Rails::Runtime).to receive(:external_identities).and_return(service)
  end

  it "renders a shared HTML/Turbo confirmation with an enabled no-JS POST" do
    post "/sign-in/providers/google_oauth2"
    expect(response).to have_http_status(:ok)
    expect(response.headers["Referrer-Policy"]).to eq("same-origin")
    expect(response.body).to include('name="referrer" content="same-origin"')
    expect(response.body).to include("Continue to Google", 'action="/auth/google_oauth2"', 'data-turbo="false"')
    expect(service).to have_received(:begin_transaction).with(configuration_id: "google", browser_secret: a_kind_of(String), purpose: :sign_in)

    post "/sign-in/providers/google_oauth2", headers: {"Accept" => "text/vnd.turbo-stream.html"}
    expect(response).to have_http_status(:ok)
    expect(response.body).to include('target="add_auth-content"', 'action="update"', "/auth/google_oauth2")
  end

  it "does not create a provider transaction when Rails rejects a forged preparation POST" do
    previous = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    post "/sign-in/providers/google_oauth2"
    expect(response).to have_http_status(:unprocessable_entity)
    expect(service).not_to have_received(:begin_transaction)
  ensure
    ActionController::Base.allow_forgery_protection = previous
  end

  it "applies the configured provider challenge before creating a transaction" do
    previous = [AddAuth.configuration.challenge, AddAuth.configuration.challenge_on]
    AddAuth.configuration.challenge_on = [:provider]
    AddAuth.configuration.challenge = AddAuth::Core::Challenge::Test.new(mode: :rejected)
    post "/sign-in/providers/google_oauth2"
    expect(response.status).to eq(422)
    expect(service).not_to have_received(:begin_transaction)
  ensure
    AddAuth.configuration.challenge, AddAuth.configuration.challenge_on = previous
  end

  it "bounds anonymous provider transaction creation with the real intake limiter" do
    30.times do
      post "/sign-in/providers/google_oauth2"
      expect(response.status).to eq(200)
    end
    post "/sign-in/providers/google_oauth2"
    expect(response.status).to eq(429)
    expect(response.headers["Retry-After"]).to eq("300")
    expect(service).to have_received(:begin_transaction).exactly(30).times
  end

  it "fails a callback that did not pass through the provider correlation middleware" do
    post "/auth/google_oauth2/callback", params: {code: "forged", state: "forged"}
    expect(response).to have_http_status(:unprocessable_entity)
    expect(service).not_to have_received(:begin_transaction)
  end
end
