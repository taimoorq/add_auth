# frozen_string_literal: true

require "spec_helper"
require "rails"
require_relative "../support/optional_confirmation_host"

RSpec.describe "Optional confirmation in a stock Rails host" do
  it "installs the candidate and exercises configuration, registration, recovery and browser contracts" do
    Dir.mktmpdir("add-auth-optional-stock-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: %w[rspec-rails capybara selenium-webdriver])
      host.run("generate", "authentication")
      host.run("db:migrate")
      OptionalConfirmationHost.prepare(host)
      expect(OptionalConfirmationHost.verify(host)).to include("0 failures")
    end
  end
end
