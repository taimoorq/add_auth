# frozen_string_literal: true

require_relative "../support/external_identity_host"

RSpec.describe "Unconfigured provider routes", type: :request, database: true do
  it "keeps provider pages unavailable and the stock password path usable" do
    expect(AddAuth.configuration.external_identities.enabled).to be(false)
    get "/account/external-identities"
    expect(response.status).to eq(404)
    get "/account/sign-up/providers/google_oauth2"
    expect(response.status).to eq(404)
    post "/sign-in/providers/google_oauth2"
    expect(response.status).to eq(404)
    get "/sign-in"
    expect(response.status).to eq(200)
    expect(response.body).not_to include("Continue with Google")
    User.create!(email_address: "stock@example.test", password: "correct-password")
    post "/sign-in/password", params: {email_address: "stock@example.test", password: "correct-password"}
    expect(response.status).to eq(303)
    expect(Session.count).to eq(1)
  end
end
