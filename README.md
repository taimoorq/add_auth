# Latchkey

**0.2.0.dev (prerelease):** password, email-link and passkey sign-in extend
Rails' generated authentication. Latchkey adds hardened sessions, verification
for sensitive actions, passkey management and email recovery with an optional
strict policy. Turnstile and reCAPTCHA integrations are available. See
[ROADMAP.md](ROADMAP.md) for verification and release gates.

Latchkey builds on top of Rails 8's built-in login system instead of
replacing it -- it keeps using your existing `User` and `Session` models.

Read the [documentation](https://latchkeygem.com) for setup guides, configuration
reference and troubleshooting.

## Development checkout hardening

The following changes are local development work and are not yet included in a
published package or public checkout:

- Authentication budgets remain five attempts per identifier and 30 per IP,
  per action. Overlapping counters prevent a fresh burst at a five-minute
  boundary; a limit can last up to six minutes. Attempts that are denied also
  count. The shared cache must support atomic increments and retain counters
  for six minutes. Keep server clocks synchronized and monitor cache eviction.
  Upgrade every web worker to apply the new bound; changing the counter format
  resets existing rate budgets once during deployment.
- Anonymous passkey sign-in options share an additional budget across IPs:
  `config.passkeys.anonymous_limit = 1000`. Set a positive integer appropriate
  to your traffic. Exhaustion returns 429 before creating a ceremony; bound
  reauthentication, registration and completion retain their separate gates.
  This limits creation rate, not total retained rows during a cleanup outage.
- Schedule `bin/rails latchkey:deliver_pending` every minute with the same
  configuration and shared cache as the web processes. It removes expired
  ceremonies and records completion using the cache's read/write operations.
  In production, `bin/rails latchkey:doctor`
  reports missing cleanup after two minutes without a success. If it reports
  that problem, inspect the scheduler's errors, run the task, then rerun doctor.
  A single manual success does not verify that the recurring schedule works.
- Invalid passkey RP/origin/support settings return a generic 503 with
  `Retry-After: 60`; doctor identifies the configuration problem. Removing a
  step-up purpose during verification returns the browser safely to `/`, and
  subsequent protected actions still require a currently allowed purpose.

Rate limiting complements the independent IP/account budgets described in
[OWASP's authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling).
Configure Rails' allowed hosts and trusted proxies at deployment; request origin
checks still require valid CSRF tokens. Live captcha providers and physical or
hybrid passkey devices retain the acceptance gates in [ROADMAP.md](ROADMAP.md).

## Quickstart

Get password and email-link sign-in working in a Rails 8 app in a few minutes.
This is enough to try Latchkey on your laptop; read "Set it up for real use"
below before you put it in front of real users.

1. Add the exact prerelease version once it appears on the
   [RubyGems versions page](https://rubygems.org/gems/latchkey/versions):

   ```ruby
   # Gemfile
   gem "latchkey", "0.2.0.dev"
   ```

   For an unpublished local checkout, use
   `gem "latchkey", path: "/path/to/latchkey"` instead.

   ```sh
   bundle install
   ```

2. If your app doesn't already have Rails' built-in login system, add it
   first:

   ```sh
   bin/rails generate authentication
   ```

3. Add Latchkey:

   ```sh
   bin/rails generate latchkey:install
   bin/rails generate latchkey:email_link
   bin/rails db:migrate
   ```

   This adds password sign-in *and* "email me a sign-in link" as ways to log
   in, plus a page where a signed-in user can see their active sessions and
   sign out of one remotely.

4. Set these values in `config/initializers/latchkey.rb`:

   ```ruby
   Latchkey.configure do |config|
     config.base_url = "http://localhost:3000"
     config.mail_from = "Latchkey <sign-in@example.test>"
     config.rate_limit_store = ActiveSupport::Cache::MemoryStore.new
   end
   ```

   For a local trial, add this to `config/environments/development.rb`:

   ```ruby
   config.active_job.queue_adapter = :inline
   config.action_mailer.delivery_method = :file
   config.action_mailer.file_settings = {location: Rails.root.join("tmp/mail")}
   config.action_mailer.perform_deliveries = true
   config.action_mailer.raise_delivery_errors = true
   ```

5. Create a trial account in `bin/rails console` using your own test address and
   password, then start `bin/rails server` and visit `/sign-in`. Request a link
   for that account and open the message written under `tmp/mail`. Treat these
   local messages as credentials and delete them after testing. Raw sign-in
   links are deliberately excluded from application logs.

These memory/inline/file adapters are for a local trial. Use the shared cache,
durable queue and real mail transport described below for deployment.

## Set it up for real use

`latchkey:install` just writes the configuration file and runs a quick health
check -- it doesn't turn anything on by itself. `latchkey:email_link` is the
one that does the real work: it also sets up hardened sessions, adds the
sign-in routes, and creates the database tables sign-in links are stored in.
If you only want hardened sessions and don't need email sign-in yet, run
`bin/rails generate latchkey:session_upgrade` instead. It's safe to run these
generators again later -- they won't overwrite changes you've already made.

```ruby
Latchkey.configure do |config|
  config.base_url = "https://accounts.example.com"
  config.mail_from = "Accounts <sign-in@example.com>"
  config.rate_limit_store = Rails.cache
  # Only let certain accounts sign in, e.g. skip unconfirmed or banned users:
  # config.eligible = ->(user) { user.confirmed? && !user.disabled? }
end
```

Before real users touch this, make sure of three things:

- **Email actually sends.** Configure Action Mailer's SMTP settings for
  whatever provider you use.
- **Background jobs survive a restart.** Sign-in emails are sent as a
  background job, so use a real Active Job backend like Sidekiq or Solid
  Queue -- not Rails' default in-memory one, which forgets everything on
  deploy.
- **Your cache is shared across servers**, e.g. Redis, Memcached or Solid
  Cache -- not each server's own memory. Otherwise sign-in rate limits only
  apply per-server instead of across your whole app.

Then schedule this to run at least once a minute, however you run scheduled
jobs (cron, `whenever`, your platform's scheduler):

```sh
bin/rails latchkey:deliver_pending
```

It retries pending sign-in emails and erases expired delivery ciphertext. Keep an eye on failed background jobs -- a stuck one
means an email that never went out.

If a mail callback or interceptor intentionally cancels a message, Latchkey
cancels that link too and emits `delivery_cancelled.latchkey` with its issuance
ID. The sweep will not resend cancelled mail. Transport failures remain retryable;
keep delivery errors enabled so failures can be detected.

Run `bin/rails latchkey:doctor` any time after changing configuration. It
double-checks your migrations, your `base_url`, your mail and background-job
setup, and your CAPTCHA setup (if you turned one on), and tells you exactly
what's missing. It also checks enabled passkey, reauthentication, recovery,
notification and ejection wiring. Deployment acceptance remains in
[ROADMAP.md](ROADMAP.md).

Visit `/sign-in` to sign in with a password, or to request an email link
instead when email is enabled. Clicking the emailed link opens a confirmation page -- you still
have to click a button there to actually sign in. That extra click matters:
it stops email scanners and link-preview bots from signing you in just by
opening your inbox. The original `/session/new` and every route to `SessionsController#create`
use the same protected sign-in flow. The host controller file is preserved, but
its `new`/`create` actions are handled by Latchkey once session adoption is enabled.
Move custom sign-in presentation into Latchkey's ejected views and verify custom
controller hooks before adoption. Password reset remains owned by Rails. Changing a password or email address automatically signs
out other sessions and cancels any pending sign-in links, as long as the
change goes through Rails and not a direct database update.
Password and address changes cancel existing email links even while email sign-in
is temporarily disabled.
Signing in again on the same browser retires its previous session; sessions on
other browsers remain available until they expire or are revoked.

Signed-in users can visit `/sessions` to see their active sessions and sign one
of them out remotely. It shows a rough description of each one (like browser
and device) and never anything that could be used to impersonate it. The
“Sign out everywhere” path requires fresh password proof by default. With
reauthentication enabled it also accepts other methods allowed for that purpose.
Confirmation revokes every active session, including this browser, and redirects
to sign-in.

If your app already has real logged-in users, deploying this will sign all of
them out -- unless you set `config.session.legacy_bridge_until` to a cutoff
date, which gives existing sessions a grace period before they're required to
sign in again. New sign-ins work fine either way. Once hardened sessions are
on, don't roll that change back -- it would weaken security for anyone who
already upgraded. If your app has a heavily customized login setup already,
or a database other than SQLite or PostgreSQL, test this
carefully before relying on it in production.

## Block bots with a CAPTCHA (optional)

Latchkey can show a Cloudflare Turnstile or Google reCAPTCHA check before
someone can sign in or request an email link. This is entirely optional --
skip it if you don't need it yet.

1. Sign up for Turnstile or reCAPTCHA (whichever you'd rather use) and get a
   site key and a secret key from them.
2. Run one command:

   ```sh
   bin/rails generate latchkey:challenge turnstile
   # or, for reCAPTCHA:
   bin/rails generate latchkey:challenge recaptcha --version=v2
   ```

3. Set the two keys as environment variables (in your `.env` file locally, or
   your hosting provider's environment settings in production):

   ```
   TURNSTILE_SITE_KEY=...
   TURNSTILE_SECRET_KEY=...
   TURNSTILE_ALLOWED_HOSTNAMES=accounts.example.com
   ```

That's it. The sign-in and email-link forms already know how to show the
widget -- you don't need to change any views. Outside production, missing keys leave the check off with a warning.
In production, a generated provider initializer requires both keys and an
explicit hostname allowlist; missing configuration prevents boot. For Google,
use `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY` and
`RECAPTCHA_ALLOWED_HOSTNAMES`. Test with keys matching the selected v2/v3 mode.
Add `:reauthenticate` to `challenge_on` if revoke-all should also require captcha.

One thing worth knowing: if Turnstile or reCAPTCHA itself ever goes down,
Latchkey's default is to block sign-in rather than let everyone through
unchecked. If you'd rather let people sign in during that kind of outage than
lock everyone out, set `config.challenge_when_unavailable = :open` in
`config/initializers/latchkey.rb`.

## Change how long sessions and links last (optional)

Latchkey ships with sensible defaults, but you can adjust them:

- A signed-in session lasts **12 hours**, or **30 minutes of no activity**,
  whichever comes first.
- An emailed sign-in link stays valid for **20 minutes**.

To change any of these, edit `config/initializers/latchkey.rb`:

```ruby
Latchkey.configure do |config|
  config.session.lifetime = 24.hours              # how long a session lasts, total
  config.session.idle_timeout = 1.hour             # how long before inactivity signs someone out
  config.email_link.token_lifetime = 10.minutes    # how long an emailed link stays clickable
end
```

There's no need to touch these unless your app has specific requirements --
the defaults follow common security guidance.

## Style the login pages

The default CSS uses scoped `latchkey-*` classes and `--latchkey-*` properties.
It has no global reset or framework dependency. The gem serves its CSS and Turbo
from fixed same-origin routes, including in hosts without an asset pipeline.
Token pages use a minimal layout without analytics or third-party assets.

To use Bootstrap, point to your compiled, same-origin stylesheet and replace
semantic classes:

```ruby
config.stylesheet = "/stylesheets/authentication.css"
config.css_classes = {
  body: "bg-body-tertiary p-3", panel: "container bg-white p-4",
  field: "mb-3", input: "form-control", button: "btn btn-primary w-100",
  notice: "alert alert-danger", muted: "text-body-secondary", link: "link-primary"
}
```

Tailwind uses the same interface:

```ruby
config.stylesheet = "/stylesheets/authentication.css"
config.css_classes = {
  body: "bg-slate-50 p-4 text-slate-900",
  panel: "mx-auto mt-8 max-w-md bg-white p-6",
  field: "my-5", input: "block w-full rounded border border-slate-500 p-3",
  button: "w-full rounded bg-emerald-800 p-3 font-semibold text-white focus-visible:outline-2 focus-visible:outline-offset-2",
  notice: "my-4 border-l-4 p-3", muted: "text-slate-600", link: "text-emerald-800 underline"
}
```

Include the initializer and any ejected views in Tailwind's class detection.
For Tailwind v4, use `@source` when they fall outside automatic detection; v3
uses the `content` configuration. See [Tailwind's source detection guide](https://tailwindcss.com/docs/detecting-classes-in-source-files).
Latchkey does not install either framework. Verify contrast/focus in your theme.

Set `config.stylesheet = nil` to render without a stylesheet. To own the markup,
run `bin/rails generate latchkey:views --only=email_link` or
`bin/rails generate latchkey:views --only=sessions`; customize the copied
partials and dedicated layout, keeping form actions, CSRF fields, cache directives
and secret-free assets. Prefer class overrides when markup can stay shared.
See the ejection and upgrade instructions below.

## Browser-bound email and reauthentication

Ordinary email links work across devices by default. After running the current
`latchkey:email_link` generator and its additive migration, set
`config.email_link.same_browser = true` to require the requesting browser. A
wrong-browser attempt does not consume the link. Existing bound links stay bound
when the option is disabled; enabling it rejects outstanding unbound links.
Do not roll back to a reader that ignores browser binding while bound links live.

Run `bin/rails generate latchkey:step_up` and `bin/rails db:migrate` to install
password and email reauthentication, including the session/email prerequisites.
Declare the purposes your host exposes:

```ruby
Latchkey.configure do |config|
  config.step_up.purposes = {
    manage_profile: {
      methods: [:password, :email_link],
      label: "update your profile",
      return_to: "/account/security"
    }
  }
end
```

`return_to` is a fixed local GET confirmation page. Successful verification rotates
the existing session bearer; an email verification is always tied to the initiating
account, session, browser and purpose and expires after five minutes. Neither path
replays a submitted mutation. Ordinary sign-in links cannot be used for elevation.

In a host controller, `require_elevated_session purpose: :manage_profile,
only: :update` provides navigation to the verification page. At the actual write,
use `with_elevated_session(purpose: :manage_profile) { |account| ... }` and check its
`Latchkey::Result`. Perform your resource ownership, authorization and target/version
checks inside that database block; do not make network calls while it holds the
account lock. It must own the transaction and cannot run inside an outer one.
The authentication proof is reusable for the configured freshness window; the
host owns single-use business confirmation and idempotency. Reset, revocation,
expiry and credential changes invalidate the appropriate evidence. An unknown
purpose or unavailable required method denies access.

`bin/rails generate latchkey:views --only=step_up` ejects the shared templates.
Passkey-only purposes require verified browser user verification. A method label
or recent password/email timestamp cannot satisfy that requirement.


## Passkeys, recovery and security mail

Run the feature generator and review its additive migrations before enabling traffic:

```sh
bin/rails generate latchkey:passkeys
bin/rails db:migrate
```

It installs the session, email, step-up and notification prerequisites. Configure
stable deployment identity and your host's verified recovery address explicitly:

```ruby
Latchkey.configure do |config|
  config.passkeys.rp_id = "example.com"
  config.passkeys.origins = ["https://accounts.example.com"]
  config.passkeys.name = "Your app"
  config.trusted_recovery_address = ->(user) { user.email_address if user.confirmed? }
  config.support_url = "/support"
end
```

`confirmed?` is a host example; return an address only when the host has verified
that it belongs to the account. Without this callback, email replacement is
unavailable. HTTP is accepted only for local development loopback origins. Keep
RP ID stable across deploys; changing it makes existing credentials unusable.
Origins must be exact HTTPS origins within that RP ID and cannot be public suffixes.
The support path must lead to your real, documented recovery process.

Visit `/passkeys` after sign-in. Adding or removing credentials requires fresh
proof for `manage_passkeys`; the page directs users to `/reauthenticate` when
needed. The native browser prompt supports available device and security-key
choices. Sign-in supports explicit passkey selection and conditional autofill.
Registration requires a discoverable credential and user verification; all
assertions require server-verified user verification too. JavaScript is required.
A browser without it displays an unavailable state and permitted alternatives.

Default recovery starts at `/recover`. A delivered recovery link expires in
20 minutes and requires explicit confirmation. Its replacement grant uses the configured freshness window (ten minutes by
default), independently of ordinary sign-in or email reauthentication. Only
successful replacement revokes other sessions and outstanding proofs, rotates the
current bearer and sends a security notice. Existing credentials remain listed
for deliberate removal. The last usable method cannot be removed.

Strict policy is per account and must be explicitly acknowledged after fresh
passkey verification. It disables password, ordinary email and email recovery;
password resets or feature toggles cannot turn those methods back on. Activating
or relaxing it revokes other sessions and pending proofs. Strict accounts need a
remaining passkey or the host's documented support process; Latchkey does not
supply recovery codes. Keep strict enforcement installed during maintenance and
rollback.

`sign_out_everywhere` also accepts the configured allowed verification methods.
A successful proof returns to a separate confirmation page; it does not replay
the sign-out request. Hosts may declare their own purposes using the same API.

`latchkey:notifications` can also be installed independently with hardened
sessions. It sends notices for password/address changes, credential addition or
removal, policy changes and completed recovery. Address changes notify both old
and new addresses. Notifications use an encrypted durable outbox and the same
lease/retry/cancellation machinery as sign-in mail; they contain no secret links.
Schedule `bin/rails latchkey:deliver_pending` at least every minute for interrupted
queue handoffs, retries and expired-secret cleanup. Ambiguous transport failures
can duplicate the same message; they do not create a new authentication proof.
Keep Action Mailer's delivery errors enabled.

All account, session, credential, ceremony, email-proof and notification tables
must use the same database connection pool. Cross-database authentication writes
are rejected. SQLite and PostgreSQL have real-store concurrency coverage; other
adapters need their own contracts before adoption.

## Ejection and upgrades

```sh
bin/rails generate latchkey:views
bin/rails generate latchkey:controllers
bin/rails generate latchkey:javascript
bin/rails generate latchkey:mailer_views
bin/rails latchkey:doctor
```

Generators preserve existing files. New copies carry a version/source fingerprint;
`config/latchkey-ejections.json` retains their pristine upstream baseline. Commit
that manifest with your host customizations. Doctor identifies customized or
missing files and prints upstream changes after a gem upgrade. Apply and review
those changes manually. To accept a reviewed upstream baseline, remove only its
reviewed file entries from the manifest and rerun the relevant ejection generator;
existing host files stay intact. Keep unreviewed entries so doctor continues to
report them. Rerunning a generator never silently advances
an old baseline or overwrites your code. Keep controller policy calls, browser
cleanup, CSRF and cache protections intact.

`latchkey:views --only=passkeys` includes management and recovery; `--only=step_up`
includes reauthentication. Ejected JavaScript lives in `app/javascript/latchkey`
and is served by the fixed asset routes. Mailers resolve host template overrides.
The same browser suite runs with engine files and with all four surfaces ejected.

For host specs, `require "latchkey/testing"` provides framework-neutral
`Latchkey::Testing.delivered_link(mail, purpose: :sign_in)` (also
`:reauthentication` and `:recovery`) and
`Latchkey::Testing.with_virtual_authenticator(selenium_driver) { |authenticator| ... }`.
The latter removes the virtual authenticator even if the block raises; install
Selenium in the host test bundle. Latchkey itself uses RSpec.

## Operations and rollback

Run doctor after migrations and template upgrades. Expand schemas before enabling
features; generators preserve existing sessions and credentials. Keep the new
reader during rollback while browser-bound proofs or strict accounts exist.
Rolling back to code that ignores their policy can restore forbidden access.
Do not drop credential/policy columns to disable a feature.

Monitor `passkey_failure.latchkey` (reason only),
`notification_enqueue_failed.latchkey` (event ID), delivery failures/cancellations
and durable pending-outbox age. Filter credentials, transactions, token URLs and
mail bodies in proxy/APM logs as well as Rails; application filtering cannot
configure upstream infrastructure. Investigate counter-regression events as
possible cloned or reset authenticators without treating backup flags as proof
of safety. For an incident, block affected accounts through the host eligibility
policy, revoke sessions/proofs through an authorized account workflow, and retain
strict enforcement. Rotating digest or encryption keys invalidates associated
sessions/proofs or undelivered ciphertext; coordinate this with users and queues.
Validate SMTP, the durable queue, shared cache, TLS/proxy trust, retention and
support recovery in the actual deployment before serving users.


## Layout

```
lib/latchkey/
  version.rb, result.rb, configuration.rb   # entry point, closed Result type
  core/                                      # Layer 1 -- plain Ruby, no Rails.
    strategies/email_link.rb, passkey.rb     #   Every security decision lives
    challenge/                              #   provider contract, HTTP,
                                              #   Turnstile/reCAPTCHA adapters.
  rails/
    engine.rb                                # Layer 2 -- thin, non-isolated
                                              #   Rails::Engine. Wires Core into
                                              #   a host app; decides nothing.
lib/generators/latchkey/                     # install, views, controllers,
                                              #   javascript, challenge
lib/tasks/latchkey.rake                      # latchkey:doctor
spec/
```

Everything generated *into* a host app (layer 3 in the design doc) is meant to
be disposable and freely ejectable; only the `Core` ⟷ `Rails` boundary is a
stable, semver'd API. See design doc section 2 for why the split exists and
section 11 for the fingerprinted-ejection contract.

## Scope

The development source implements password/email/passkey sign-in, session
adoption and management, purpose-bound verification, passkey recovery and
strict account policy, durable security mail, and challenge adapters. Account
provisioning, address confirmation and password reset remain host responsibilities.
Live provider interoperability, deployment operations and release acceptance
remain explicit gates. Recovery codes and Latchkey-owned password policy are v2.

## Roadmap

Track v1 progress in [ROADMAP.md](ROADMAP.md) -- checked off incrementally as
each piece lands, derived from the design doc's scope decision.

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
bundle exec rspec spec/latchkey/rails/email_tokens_spec.rb
bundle exec rspec spec/generators/persistence_generator_spec.rb
bundle exec rspec spec/system/sign_in_spec.rb
bundle exec rspec spec/system/passkeys_spec.rb
LATCHKEY_EJECT_UI=1 bundle exec rspec spec/system
```

`latchkey:email_tokens` is an internal persistence generator: it creates an
additive token table migration and model for review. It does not run migrations,
change the Session table, install sign-in routes or make a host production-ready.
The low-level email lifecycle requires explicit eligibility/normalization adapters
and a same-database transaction-owned session writer; it must not be called directly from a public
request handler as an enumeration-safe endpoint. SQLite and PostgreSQL run the same store/request contracts. Other database
adapters still require their contract tests. PostgreSQL tests explicitly target a
disposable database named `latchkey_test`:

```sh
LATCHKEY_TEST_DATABASE_URL=postgresql://localhost/latchkey_test bundle exec rspec spec/latchkey/rails spec/requests
```

Disabling `config.email_link.enabled` rejects new email requests and hides the
email form while retaining hardened session reading and revocation. Expired
outbox ciphertext is scrubbed and expired WebAuthn ceremonies are deleted by
`deliver_pending`; the task retains historical token and notification receipts. Set a host retention policy and schedule bounded purges of
expired rows after your audit-retention period. Keep proxy trust configured in
Rails, test Secure/HttpOnly/SameSite cookies through your TLS terminator, and
verify atomic cache increments across every app instance. Doctor checks local
configuration and schema; it cannot prove your mail provider, proxy, cache cluster
or recovery procedures work in production.

## Contributing

Not yet accepting contributions -- v1 doesn't exist yet. Filing issues that
poke holes in the design doc or the roadmap is welcome.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
