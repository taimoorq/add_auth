# frozen_string_literal: true

require "spec_helper"
require "add_auth/testing"
require "mail"

RSpec.describe AddAuth::Testing do
  it "extracts only the requested delivered proof and rejects ambiguous messages" do
    mail = Mail.new(body: "Verify https://example.test/reauthenticate/link?token=proof")
    expect(described_class.delivered_link(mail, purpose: :reauthentication).request_uri).to eq("/reauthenticate/link?token=proof")
    expect { described_class.delivered_link(mail) }.to raise_error(ArgumentError)
    mail.body = "https://example.test/sign-in/link?token=one https://example.test/sign-in/link?token=two"
    expect { described_class.delivered_link(mail) }.to raise_error(ArgumentError)
  end

  it "removes a virtual authenticator even when a browser assertion fails" do
    driver, authenticator = double, double(valid?: true)
    allow(driver).to receive(:add_virtual_authenticator).and_return(authenticator)
    expect(authenticator).to receive(:remove!)
    expect { described_class.with_virtual_authenticator(driver) { raise "browser failed" } }.to raise_error("browser failed")
  end
end
