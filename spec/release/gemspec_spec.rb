# frozen_string_literal: true

require "spec_helper"
require "rubygems/package"

RSpec.describe "release package" do
  it "declares the shipped runtime surface and release safeguards" do
    specification = Gem::Specification.load(File.expand_path("../../add_auth.gemspec", __dir__))
    expect(specification.name).to eq("add_auth")
    expect(specification.version.to_s).to eq(AddAuth::VERSION)
    expect(specification.files).to include("lib/add_auth.rb", "lib/add_auth/rails/engine.rb")
    expect(specification.files.grep(/latchkey/i)).to be_empty
    expect(specification.files).to include(
      "app/controllers/add_auth/sign_ins_controller.rb",
      "app/controllers/add_auth/sessions_controller.rb",
      "app/views/add_auth/sign_ins/_form.html.erb",
      "app/views/add_auth/sessions/index.html.erb",
      "app/views/add_auth/sessions/_revoke_all.html.erb",
      "lib/add_auth/core/step_up.rb",
      "lib/add_auth/core/challenge/turnstile.rb",
      "lib/add_auth/core/challenge/recaptcha.rb",
      "lib/generators/add_auth/email_link/templates/add_auth_challenge.js",
      "lib/generators/add_auth/session_upgrade/session_upgrade_generator.rb"
    )
    expect(specification.metadata["allowed_push_host"]).to eq("https://rubygems.org")
    expect(specification.metadata["rubygems_mfa_required"]).to eq("true")
  end
end
