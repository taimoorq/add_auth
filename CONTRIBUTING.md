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

CI runs both lines on Ruby 3.3, 3.4 and 4.0 for each pull request. It checks out
the PR head explicitly; branch protection requires it to be up to date before
merge. Merging does not repeat the full suite. Release verification reuses the
latest successful PR run only when the merged commit has the same complete Git
tree, and all required checks belong to that run and head. Changed files, failed
or pending reruns, and missing provenance block publication. CodeQL and the
owner-approved OIDC publishing environment remain separate gates.

To request fresh CI on the default branch, run
`gh workflow run ci.yml --ref master`. A successful exact-commit manual run can
also satisfy release verification. This does not bypass required PR checks.

Focused commands:

```sh
bundle exec rspec spec/add_auth/rails/email_tokens_spec.rb
bundle exec rspec spec/generators/persistence_generator_spec.rb
bundle exec rspec spec/system/sign_in_spec.rb
bundle exec rspec spec/system/passkeys_spec.rb
ADD_AUTH_EJECT_UI=1 bundle exec rspec spec/system
ADD_AUTH_TURBO=0 bundle exec rspec spec/system
ADD_AUTH_TURBO=0 ADD_AUTH_EJECT_UI=1 bundle exec rspec spec/system
```

Browser changes must pass in bundled and ejected UI with Turbo enabled, with
JavaScript enabled and Turbo absent (`ADD_AUTH_TURBO=0`), and with JavaScript
disabled (covered by the same suite). The plain navigation run exercises real
passkey and captcha modules too. Keep this matrix when adding browser journeys;
no-JS coverage alone does not establish operation without Turbo.

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

The UUID and mixed-key acceptance fixture requires Chrome and the disposable
`add_auth_external_test` PostgreSQL database. It creates and removes its own
random schemas, installs the built candidate into stock generated Rails hosts,
and checks all primary/foreign keys plus session, mail, mobile and WebAuthn flows.
It also verifies bundled/ejected session navigation with Turbo, JavaScript without
Turbo, and no JavaScript. From this checkout:

```sh
ADD_AUTH_KEYS_DATABASE_URL=postgresql://localhost/add_auth_external_test BUNDLE_GEMFILE=gemfiles/rails_8_1.gemfile bundle exec rspec spec/keys/authentication_tables.rb
```

Run this on both supported Rails lines; replace `8_1` with `8_0` for the other.
The normal root suite retains the default integer/SQLite installation coverage.

## Optional account and OAuth development acceptance

Account migration and external identities are development work and remain
disabled by default. Provider gems belong to the host's bundle. AddAuth must
preserve their registration, scopes, CSRF validator, failure handler and unrelated
routes; protocol exchange and verification stay in those libraries.

From this checkout, run the synthetic source/destination and browser fixtures:

```sh
BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle install
BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle exec rspec spec/migration/*.rb
BUNDLE_GEMFILE=gemfiles/providers_rails_8_1.gemfile bundle install
createdb add_auth_external_test
ADD_AUTH_MICROSOFT_DATABASE_URL=postgresql://localhost/add_auth_external_test BUNDLE_GEMFILE=gemfiles/providers_rails_8_1.gemfile bundle exec rspec spec/providers/*.rb
ADD_AUTH_EJECT_UI=1 ADD_AUTH_MICROSOFT_DATABASE_URL=postgresql://localhost/add_auth_external_test BUNDLE_GEMFILE=gemfiles/providers_rails_8_1.gemfile bundle exec rspec spec/providers/google_sign_in.rb spec/providers/apple_form_post.rb spec/providers/microsoft_browser.rb
```

Use `createdb` only when that dedicated test database does not already exist.
Substitute `8_0` for the other supported Rails line. Chrome and local PostgreSQL
are required; absent prerequisites fail rather than skip acceptance. Provider
fixtures install the built candidate in disposable hosts, use synthetic local
identity providers and exercise the actual protocol libraries. Google and Apple
intercept specific remote HTTP endpoints; Microsoft uses local HTTP throughout.
Apple uses a temporary HTTPS certificate and verifies cross-site cookie behavior.
No live provider account or production credential is used.

Google's host tests independent confirmation, provider-only recovery/password
enrollment, remembered sessions, linking/unlinking and deletion. Browser fixtures
check Turbo, ordinary JavaScript with Turbo absent and permitted no-JS navigation;
Microsoft's UUID profile uses PostgreSQL. Ejection checks assert that the provider
partials were actually copied. The default RSpec suite still runs without these
optional gems. Serialize commands that boot `spec/dummy`; separate generated hosts
have their own databases or unique test schemas.

## Optional confirmation integration rehearsal

This section targets 0.4.0. Use a disposable Rails host with the candidate
installed, following [checkout development](#work-on-a-checkout). Application
users should use the RubyGems package after its publication; 0.3.0 does not
contain the new confirmation options.

From that host, after Rails authentication is present:

```sh
bin/rails generate add_auth:accounts --no-email-link
bin/rails db:migrate
```

Review `config/initializers/add_auth.rb`. The generated file contains the default
assignments and commented alternatives for every settings group. Existing files
are preserved: compare them with the [initializer template](lib/generators/add_auth/install/templates/initializer.rb)
and bring over only the settings you choose. Feature generators update their
own boolean enablement line, keep custom expressions, and remain repeatable.
`--no-email-link` does not disable email sign-in in a host that already enabled it.

Set these values inside the initializer's existing `AddAuth.configure` block:

```ruby
config.lifecycle.enabled = true
config.lifecycle.confirmation_required = false
# Optional, separate recovery decision:
# config.lifecycle.reset_unconfirmed = true
```

The accounts generator includes an additive `add_auth_provisioned_at` migration,
including when rerun in an existing lifecycle host. Optional confirmation refuses
to start without it. Do not backfill `confirmed_at` to enable signup. Reconcile
existing pending registrations and imported-account provisioning before changing
a host's policy; the migration invents no historical provisioning receipts.
Existing required-confirmation hosts keep their current behavior without this
optional-profile migration. Preserve receipts when rolling back application code.
An old implementation must not consume confirmation for accounts provisioned by
this profile: use a compatible rollback build or stop that intake.

Configure `eligible`, the additional `lifecycle.eligible`, profile allowlists and
`lifecycle.provision` for the host. Provisioning must use local writes on the same
account database connection and raise on failure; remote obligations need a host
transactional outbox. It may not rewrite the signup address, password or email
verification state. A failed account/provision/session transaction rolls back the
new account and its obligations. A repeated signup never signs into the existing
account; after a lost response the user signs in with their password.

Visit `/account/sign-up` and register a fresh address. You should reach the host
application immediately, with one password session, one provisioning call,
`confirmed_at: nil`, and no confirmation mail or queued delivery. A later explicit
confirmation request consumes a real address proof and does not provision again.
Signup still observes captcha, throttling, eligibility, lockout and strict policy.
Provider-only enrollment continues to require independent confirmation.

Password reset is separate. With `reset_unconfirmed: false`, an unconfirmed user
must confirm first or use the host's support process. With `true`, the holder of
the **current stored mailbox** may reset the password after consuming a bounded,
purpose-bound, exact-address, single-use proof. This policy can recover an account
registered with somebody else's address; choose it deliberately. Reset does not
confirm the address, create a session, provision, or bypass suspension/strict
policy. Previously issued authority is revoked. An unverified address remains
unavailable to trusted-recovery callbacks and unlock mail. Existing timed locks
retain their configured expiry and manual locks require the host's process.

Address changes always need fresh purpose-bound reauthentication and proof of the
new address. Until confirmation the old identifier and its actual verification
state remain intact. Password changes and deletion keep their fresh proof and
host-authorization requirements. Configure working mail and durable jobs for
these proof and notice workflows even though optional signup itself sends no mail.
Run `bin/rails add_auth:doctor` before enabling traffic.

From the gem checkout, these installed-candidate fixtures exercise the profile:

```sh
bundle exec rspec spec/generators/optional_confirmation_generator_spec.rb
bundle exec rspec spec/upgrade/confirmation_policy.rb
BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle exec rspec spec/migration/optional_confirmation.rb
ADD_AUTH_EJECT_UI=1 BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle exec rspec spec/migration/optional_confirmation.rb spec/generators/optional_confirmation_generator_spec.rb
ADD_AUTH_MIGRATION_POSTGRES=1 BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle exec rspec spec/migration/optional_confirmation.rb
```

Use a local PostgreSQL server for the UUID fixture; it creates only a random
schema in the dedicated `add_auth_migration_test` database and removes that schema
afterward. Run both Rails lines and supported Rubies. Each fixture exercises
Turbo, JavaScript with Turbo absent, and no-JS browser journeys with real CSRF,
plus registration/provisioning/reset races and rollback. Ejection runs exercise
the actual copied controller and views. The stock fixture also runs in the root
RSpec suite. Receipt counts distinguish these wrapper examples from their inner
acceptance scenarios.

## Migration execution and compatibility rollback

The migration fixtures now also execute `examples/devise_backfill.rb`, a
contributor-only recipe for isolated Rails test hosts. It delegates projection
and account locking to Core, binds the checkpoint to the reviewed source/config
and database manifest, and writes a private cursor atomically under an operator
lock. It does not select authority or perform production deployment. Review its
manifest fields before adapting it; keep the checkpoint directory mode 0700 and
checkpoint mode 0600. Resume the same manifest after interruption; conflicts or
changed source rows retain the prior cursor. Reconcile the full cohort before a
switch, including rows written after the census.

From the gem checkout:

```sh
BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle exec rspec spec/migration/backfill_checkpoint.rb spec/migration/compatible_rollback.rb
ADD_AUTH_MIGRATION_POSTGRES=1 BUNDLE_GEMFILE=gemfiles/devise_rails_8_1.gemfile bundle exec rspec spec/migration/backfill_checkpoint.rb spec/migration/compatible_rollback.rb
```

The PostgreSQL fixture creates only its dedicated `add_auth_migration_test`
database and random schemas, removing those schemas afterward. The rollback
fixture boots a fresh compatibility process after password reset, email change,
provider unlink and deletion. It retains canonical readers and tests the retired
Devise writer fence. It does not promise that any earlier Devise deployment is a
safe rollback target. Unsupported rollback means stop intake and forward repair;
restoring a database requires reconciliation of later changes and revocations.

Native session/provider fixtures run in the existing optional provider bundle:

```sh
BUNDLE_GEMFILE=gemfiles/providers_rails_8_1.gemfile bundle exec rspec spec/providers/apple_native_host.rb
ADD_AUTH_EJECT_UI=1 BUNDLE_GEMFILE=gemfiles/providers_rails_8_1.gemfile bundle exec rspec spec/providers/apple_native_host.rb
ADD_AUTH_TEST_DATABASE_URL=postgresql://localhost/add_auth_test BUNDLE_GEMFILE=gemfiles/providers_rails_8_1.gemfile bundle exec rspec spec/providers/apple_native.rb
```

They use signed synthetic Apple tokens and local client/callback fixtures.
Physical-device sign-in, live provider registrations and store uploads belong to
the adopter's deployment. The finite mobile profile requires fresh sign-in after
expiry; no rotating refresh-token family is enabled by this work.

## Local operational acceptance

With Ruby 3.4, Redis's `redis-server` executable and the optional test bundle:

```sh
BUNDLE_GEMFILE=gemfiles/operations.gemfile bundle install
BUNDLE_GEMFILE=gemfiles/operations.gemfile bundle exec rspec spec/operations/local_acceptance.rb
```

This opt-in suite starts its own loopback Redis, SMTP sink and Sidekiq worker,
using temporary state and synthetic accounts. It verifies cross-process atomic
cache increments, persisted queue recovery after Redis restart, SMTP retry using
the same issuance and completed-delivery suppression after worker restart. It
stops its own processes and removes temporary state. It does not contact real
mailboxes or use the developer's Redis/SMTP settings. Run it separately from
other suites using `spec/dummy` because they share the disposable test database.

Local acceptance does not establish delivery through a host's provider or
physical/hybrid passkey interoperability. Application maintainers verify those
conditions in their own deployment. Sidekiq and Redis are test dependencies in
this optional bundle; they are not AddAuth runtime dependencies.


## Published-package upgrade acceptance

From this checkout, fetch the official baseline and run the isolated rehearsal:

```sh
for baseline in 0.2.1 0.2.2 0.3.0 0.4.0; do
  gem fetch add_auth --version "$baseline"
  ADD_AUTH_BASELINE_GEM="$PWD/add_auth-${baseline}.gem" bundle exec rspec spec/upgrade/published_package.rb
done
```

The spec verifies the baseline archive against its recorded registry SHA256,
installs it in a temporary Rails host, persists synthetic authentication state,
installs the current built candidate, then reinstalls the baseline. It checks
pending jobs, revoked/spent authority, preserved integer keys, the additive
session-pagination index and reviewed ejections. Application upgrade instructions
live in the [public upgrade guide](https://addauthgem.com/upgrading/#uuid-support);
primary-key conversion is a separate host migration. The drift fixture
is explicitly synthetic. CI runs this command on both Rails lines and every
supported Ruby. Version equality in an unreleased checkout does not imply identical
packages; each archive is installed at its own temporary path.

Additional optional operations commands use the same operations bundle:

```sh
BUNDLE_GEMFILE=gemfiles/operations.gemfile bundle exec rspec spec/operations/solid_queue_acceptance.rb
ADD_AUTH_CACHE_TEST_URL=postgresql://localhost/add_auth_test BUNDLE_GEMFILE=gemfiles/operations.gemfile bundle exec rspec spec/operations/solid_cache_contract.rb
BUNDLE_GEMFILE=gemfiles/operations.gemfile bundle exec rspec spec/operations/maintenance_profile.rb
ADD_AUTH_TEST_DATABASE_URL=postgresql://localhost/add_auth_test BUNDLE_GEMFILE=gemfiles/operations.gemfile bundle exec rspec spec/operations/maintenance_profile.rb
```

Use a dedicated local disposable `add_auth_test` database. The cache test creates
Solid Cache tables there and demonstrates its known missing-row increment race;
it also checks AddAuth's adapter rejection. A future upstream fix must trigger a
new compatibility decision instead of silently dropping the regression. Solid
Queue's test uses separate temporary primary and queue SQLite databases and a
loopback SMTP sink. Set `ADD_AUTH_OPERATIONS_GEM` to a previously verified archive
to repeat that queue rehearsal against a published package. Optional Solid gems,
Sidekiq and Redis remain test dependencies only. Run suites sharing `spec/dummy`
sequentially; the maintenance profile prints bounded-work counts and local timings,
not a production capacity claim.
