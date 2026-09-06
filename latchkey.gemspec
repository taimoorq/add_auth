# frozen_string_literal: true

require_relative "lib/latchkey/version"

Gem::Specification.new do |spec|
  spec.name        = "latchkey"
  spec.version     = Latchkey::VERSION
  spec.authors     = [ "Taimoor Qureshi" ]
  spec.email       = [ "taimoorq@gmail.com" ]

  spec.summary     = "Passkeys and email-link sign-in for the Rails 8 authentication generator."
  spec.description = <<~DESC
    Latchkey extends the output of `bin/rails generate authentication` with the
    credentials it does not cover: passwordless email-link sign-in and WebAuthn
    passkeys (including conditional-UI autofill), plus step-up (elevated)
    sessions, pluggable Turnstile/reCAPTCHA challenges, and generated views and
    Stimulus controllers that work with Turbo and without JavaScript. It does
    not replace the generator or the Session model it creates -- it upgrades
    them in place. See docs/authentication-gem-plan.md in the companion
    workspace repo for the full design.
  DESC
  spec.homepage    = "https://github.com/taimoorq/latchkey"
  spec.license     = "MIT"
  # Rails 8.0/8.1 both tolerate Ruby >= 3.2.0 -- but the 3.2 series itself
  # reached end-of-life on 2026-03-31 (no more upstream security patches).
  # An authentication gem sets its floor at the oldest Ruby series still
  # receiving security patches, not just at whatever Rails will tolerate --
  # those are different questions that happen to be the same answer only
  # when Ruby's EOL clock and Rails' own floor haven't drifted apart.
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["homepage_uri"]      = spec.homepage
  spec.metadata["source_code_uri"]   = spec.homepage
  spec.metadata["changelog_uri"]     = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"]   = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["rubygems_mfa_required"] = "true"
  # Belt-and-suspenders alongside Trusted Publishing (see
  # .github/workflows/push_gem.yml): even if a long-lived API key were ever
  # mistakenly present in a dev environment, this refuses a push to anything
  # other than the official host.
  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = [ "lib" ]

  # Cryptographic primitives only. Everything else (sessions, tokens, views,
  # generators) is Latchkey's own code on top of Rails 8 primitives -- see
  # "Dependencies" in the design doc for why this list stays short.
  # Rails 8.0 is the actual floor: that's the release that shipped
  # `bin/rails generate authentication`, the generator this gem extends.
  spec.add_dependency "rails", ">= 8.0"
  spec.add_dependency "webauthn", "~> 3.0"
  spec.add_dependency "bcrypt", "~> 3.1.7"

  spec.add_development_dependency "rspec-rails", "~> 8.0"
  spec.add_development_dependency "sqlite3", ">= 2.1"
  spec.add_development_dependency "standard", "~> 1.3"
end
