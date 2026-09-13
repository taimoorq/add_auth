# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require_relative "../support/devise_source_host"
require_relative "../support/optional_confirmation_host"

RSpec.describe "Optional confirmation in a populated Devise destination" do
  it "retains the source cohort and proves password-only lifecycle with integer or UUID users" do
    Dir.mktmpdir("add-auth-optional-adopter-") do |directory|
      profile = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? :uuid : :standard
      host = DeviseSourceHost.new(directory)
      host.prepare(profile: profile)
      host.prepare_accounts
      host.password_destination(profile: profile, passkeys: false)
      OptionalConfirmationHost.prepare(host)
      expect(OptionalConfirmationHost.verify(host)).to include("0 failures")
    ensure
      host&.cleanup
    end
  end
end
