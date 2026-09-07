# frozen_string_literal: true

require "spec_helper"
require "rubygems/package"

RSpec.describe "release package" do
  it "declares the shipped runtime surface and release safeguards" do
    specification = Gem::Specification.load(File.expand_path("../../latchkey.gemspec", __dir__))
    expect(specification.files).to include(
      "app/controllers/latchkey/sign_ins_controller.rb",
      "app/controllers/latchkey/sessions_controller.rb",
      "app/views/latchkey/sign_ins/_form.html.erb",
      "app/views/latchkey/sessions/index.html.erb",
      "app/views/latchkey/sessions/_revoke_all.html.erb",
      "lib/latchkey/core/step_up.rb",
      "lib/latchkey/core/challenge/turnstile.rb",
      "lib/latchkey/core/challenge/recaptcha.rb",
      "lib/generators/latchkey/email_link/templates/latchkey_challenge.js",
      "lib/generators/latchkey/session_upgrade/session_upgrade_generator.rb"
    )
    expect(specification.metadata["allowed_push_host"]).to eq("https://rubygems.org")
    expect(specification.metadata["rubygems_mfa_required"]).to eq("true")
  end
end
