# frozen_string_literal: true

require_relative "lib/latchkey/version"

Gem::Specification.new do |spec|
  spec.name = "latchkey"
  spec.version = Latchkey::VERSION
  spec.authors = ["Taimoor Qureshi"]
  spec.email = ["taimoorq@gmail.com"]

  spec.summary = "Passkeys, email sign-in and session hardening for Rails 8 authentication."
  spec.description = <<~DESC
    Latchkey extends the output of `bin/rails generate authentication` with the
    credentials it does not cover: passkeys, email-link sign-in, purpose-bound
    reauthentication and recovery. It adds hardened sessions, security mail and
    challenge providers, with shared Turbo/HTML pages and permitted no-JavaScript
    alternatives. It upgrades the generated User and Session models in place.
    Documentation: https://latchkeygem.com.
  DESC
  spec.homepage = "https://latchkeygem.com"
  spec.license = "MIT"
  # Rails 8.0/8.1 both tolerate Ruby >= 3.2.0 -- but the 3.2 series itself
  # reached end-of-life on 2026-03-31 (no more upstream security patches).
  # An authentication gem sets its floor at the oldest Ruby series still
  # receiving security patches, not just at whatever Rails will tolerate --
  # those are different questions that happen to be the same answer only
  # when Ruby's EOL clock and Rails' own floor haven't drifted apart.
  spec.required_ruby_version = ">= 3.3.0"

  repository_url = "https://github.com/taimoorq/latchkey"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{repository_url}/tree/master"
  spec.metadata["changelog_uri"] = "#{repository_url}/blob/master/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{repository_url}/issues"
  spec.metadata["documentation_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"
  # Belt-and-suspenders alongside Trusted Publishing (see
  # .github/workflows/push_gem.yml): even if a long-lived API key were ever
  # mistakenly present in a dev environment, this refuses a push to anything
  # other than the official host.
  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.files = Dir.chdir(__dir__) do
    roots = Dir.glob("{app,config,exe,lib}/**/*", File::FNM_DOTMATCH)
    docs = %w[CHANGELOG.md CODE_OF_CONDUCT.md LICENSE.txt README.md ROADMAP.md SECURITY.md]
    (roots + docs).select do |file|
      File.file?(file) && !file.end_with?(".OBSOLETE") && !file.start_with?(".git")
    end.sort
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Rails/Turbo provide the host framework and progressive enhancement;
  # cryptographic libraries supply verification primitives. Authentication
  # policy and lifecycle remain in Latchkey Core.
  # Rails 8.0 is the actual floor: that's the release that shipped
  # `bin/rails generate authentication`, the generator this gem extends.
  # The transaction-owned writer also uses the public current_transaction API,
  # available at this floor; no new Rails or Ruby floor is required.
  spec.add_dependency "rails", ">= 8.0"
  spec.add_dependency "webauthn", "~> 3.4", ">= 3.4.3"
  spec.add_dependency "public_suffix", "~> 7.0"
  spec.add_dependency "turbo-rails", "~> 2.0"
  spec.add_dependency "stimulus-rails", "~> 1.3"
  spec.add_dependency "bcrypt", "~> 3.1.7"

  spec.add_development_dependency "rspec-rails", "~> 8.0"
  spec.add_development_dependency "sqlite3", ">= 2.1"
  spec.add_development_dependency "pg", "~> 1.6"
  spec.add_development_dependency "standard", "~> 1.3"

  # Passkey system specs (design doc section 13) drive a real Chromium
  # through Selenium's CDP/BiDi support to call WebAuthn.addVirtualAuthenticator
  # -- not something rack-test or any non-browser driver can do.
  spec.add_development_dependency "capybara", "~> 3.40"
  spec.add_development_dependency "selenium-webdriver", "~> 4.48"

  # Stubs the real HTTP calls Challenge::Turnstile/Recaptcha make to their
  # verification endpoints, so those adapters' specs don't hit the network
  # (or silently pass/fail based on whether a provider happens to be up).
  spec.add_development_dependency "webmock", "~> 3.26"
end
