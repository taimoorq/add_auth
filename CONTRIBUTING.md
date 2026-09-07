# Contributing to AddAuth

This guide is for working on the gem’s source. To install AddAuth in a Rails
application, follow the [RubyGems quickstart](https://addauthgem.com/quickstart/).

Public issues are open for bug reports and feedback. Pull requests are currently
restricted to collaborators. Report vulnerabilities privately through
[SECURITY.md](SECURITY.md).

## Work on a checkout

```sh
git clone https://github.com/taimoorq/add_auth.git
cd add_auth
```

For a separate development host testing changes to this checkout, use its
absolute path in that host’s Gemfile:

```ruby
gem "add_auth", path: "/path/to/add_auth"
```

Run `bundle install` in that host after changing the Gemfile. This local dependency
is for gem development; application installation uses the RubyGems package.

## Layout

```
lib/add_auth/
  version.rb, result.rb, configuration.rb   # entry point, closed Result type
  core/                                      # Layer 1 -- plain Ruby, no Rails.
    strategies/email_link.rb, passkey.rb     #   Every security decision lives
    challenge/                              #   provider contract, HTTP,
                                              #   Turnstile/reCAPTCHA adapters.
  rails/
    engine.rb                                # Layer 2 -- thin, non-isolated
                                              #   Rails::Engine. Wires Core into
                                              #   a host app; decides nothing.
lib/generators/add_auth/                     # install, views, controllers,
                                              #   javascript, challenge
lib/tasks/add_auth.rake                      # add_auth:doctor
spec/
```

Core owns security decisions; the Rails layer wires them into the host. See
[the ejection guide](https://addauthgem.com/customization/) for how application
users customize generated presentation.

## Development and verification

From this repository, using Ruby 3.3 or newer:

```sh
bundle install
bundle exec rspec
bundle exec standardrb
```

The suite boots `spec/dummy`, generates its token persistence model/migration,
uses its disposable SQLite test database, and generates a separate temporary Rails
host. It verifies host password sign-in/reset/sign-out, encrypted delivery intent,
replay, real database races, rollback, address changes and generator repeatability.
Chrome system specs exercise delivered email, password and passkey journeys,
including a virtual authenticator, conditional mediation, replacement recovery,
strict denial, frame breakout, real CSRF and JavaScript-disabled alternatives. Install Chrome or
Chromium for the full suite; Selenium manages the matching driver.

Run a supported Rails line explicitly after installing its bundle:

```sh
BUNDLE_GEMFILE=gemfiles/rails_8_0.gemfile bundle install
BUNDLE_GEMFILE=gemfiles/rails_8_0.gemfile bundle exec rspec
BUNDLE_GEMFILE=gemfiles/rails_8_1.gemfile bundle install
BUNDLE_GEMFILE=gemfiles/rails_8_1.gemfile bundle exec rspec
```

CI runs both lines on Ruby 3.3, 3.4 and 4.0. Focused commands:

```sh
bundle exec rspec spec/add_auth/rails/email_tokens_spec.rb
bundle exec rspec spec/generators/persistence_generator_spec.rb
bundle exec rspec spec/system/sign_in_spec.rb
bundle exec rspec spec/system/passkeys_spec.rb
ADD_AUTH_EJECT_UI=1 bundle exec rspec spec/system
```

`add_auth:email_tokens` is an internal persistence generator: it creates an
additive token table migration and model for review. It does not run migrations,
change the Session table, install sign-in routes or make a host production-ready.
The low-level email lifecycle requires explicit eligibility/normalization adapters
and a same-database transaction-owned session writer; it must not be called directly from a public
request handler as an enumeration-safe endpoint. SQLite and PostgreSQL run the same store/request contracts. Other database
adapters still require their contract tests. PostgreSQL tests explicitly target a
disposable database named `add_auth_test`:

```sh
ADD_AUTH_TEST_DATABASE_URL=postgresql://localhost/add_auth_test bundle exec rspec spec/add_auth/rails spec/requests
```

