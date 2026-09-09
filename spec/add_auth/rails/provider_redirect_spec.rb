# frozen_string_literal: true

require "rails_helper"

# Targeted CodeQL finding reproduction: keep the real controller's URL resolver,
# session finalizer and Rails redirect sink. Only the already-verified provider
# result is supplied by a double; provider protocol acceptance runs separately.
RSpec.describe AddAuth::ProviderSignInsController, type: :controller, database: true do
  [nil, "https://evil.test/path", "//evil.test/path", "/\\evil.test", "/%2f%2fevil.test", "/%252f%252fevil.test", "/\nlocation", "javascript:alert(1)", "/", "/settings?tab=profile"].each do |destination|
    it "constrains the actual provider redirect for #{destination.inspect}" do
      user = User.create!(email_address: "redirect-audit@example.test", password: "correct-password")
      grant = AddAuth::Rails::Runtime.sessions.start(user: user, method: :password)
      expect(grant).not_to be_nil
      expect(controller.method(:after_authentication_url).owner).to eq(AddAuth::Rails::Authentication)
      controller.set_response!(response)
      request.session[:return_to_after_authenticating] = destination
      result = double(success?: true, grant: grant)
      allow(controller).to receive(:service).and_return(double(sign_in: result))
      allow(controller).to receive(:correlation_remember?).and_return(false)
      controller.send(:finish_sign_in, :verified_fixture_evidence)
      expected = ["/", "/settings?tab=profile"].include?(destination) ? destination : "/"
      expect(response.status).to eq(303)
      expect(URI(response.location).host).to eq(request.host)
      expect(URI(response.location).request_uri).to eq(expected)
      expect(request.session[:return_to_after_authenticating]).to be_nil
      expect(Current.session).to eq(grant.session)
    end
  end
end
