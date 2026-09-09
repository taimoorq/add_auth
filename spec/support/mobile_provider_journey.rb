# frozen_string_literal: true

RSpec.shared_examples "a provider browser-to-mobile handoff" do |variants, callback_contract|
  variants.each do |variant|
    it "exchanges the #{variant} browser handoff once without browser authority" do
      @fixture.start(**variant, mobile: true)
      result = @fixture.submit
      expect(result.fetch("sessions")).to be_empty
      expect(result.fetch("callbacks").last).to include(callback_contract)
      expect(@fixture.browser.find_element(tag_name: "body").text).to include("Return to the app")
      expect(@fixture.mobile_fields.fetch("code")).to match(/\Aah1:[A-Za-z0-9_-]{43}\z/)
      denied = @fixture.exchange_mobile(verifier: "wrong" * 12)
      expect(denied.code).to eq("401")
      expect(@fixture.status.fetch("sessions")).to be_empty
      exchange = @fixture.exchange_mobile
      expect(exchange.code).to eq("201")
      expect(exchange["Set-Cookie"]).to be_nil
      expect(exchange["Cache-Control"]).to eq("no-store")
      body = JSON.parse(exchange.body)
      expect(body.fetch("user_id")).to eq(result.fetch("identity_owner")) if result.key?("identity_owner")
      bearer = body.fetch("token")
      expect(bearer).to match(/\Aam1:[A-Za-z0-9_-]{43}\z/)
      expect(@fixture.exchange_mobile.code).to eq("401")
      expect(@fixture.status.fetch("sessions").size).to eq(1)
      resumed = @fixture.mobile_request("GET", "/mobile/session", bearer: bearer)
      expect(resumed.code).to eq("200")
      expect(JSON.parse(resumed.body).fetch("session_id")).to eq(body.fetch("session_id"))
      expect(@fixture.mobile_request("GET", "/mobile/session").code).to eq("401")
      expect(@fixture.mobile_request("DELETE", "/mobile/session", bearer: bearer).code).to eq("204")
      expect(@fixture.mobile_request("GET", "/mobile/session", bearer: bearer).code).to eq("401")
    end
  end
end
