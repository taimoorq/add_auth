# AddAuth

**0.2.1:** password, email-link and passkey sign-in extend
Rails' generated authentication. AddAuth adds hardened sessions, verification
for sensitive actions, passkey management and email recovery with an optional
strict policy. Turnstile and reCAPTCHA integrations are available. See
[features](https://addauthgem.com/features/) for the capabilities your app can enable.

AddAuth builds on top of Rails 8's built-in login system instead of
replacing it -- it keeps using your existing `User` and `Session` models.

Read the [documentation](https://addauthgem.com) for setup guides, configuration
reference and troubleshooting.

## Quickstart

Install the `add_auth` gem from RubyGems through your Rails app’s Gemfile,
then enable password and email-link sign-in. Use Ruby 3.3+ and Rails 8.0+
with Active Record, and run the commands below from your Rails app’s root.

**Release availability:** these commands require the published `0.2.1` package.
If it is not yet listed on [RubyGems](https://rubygems.org/gems/add_auth/versions),
wait for publication; see [release status](https://addauthgem.com/release-status/).
Start in your app’s development environment; use the deployment settings
below before enabling sign-in for users.

1. Keep `source "https://rubygems.org"` in your app’s Gemfile and add the
   0.2 release line:

   ```ruby
   # Gemfile
   gem "add_auth", "~> 0.2.1"
   ```

   Bundler downloads the package from RubyGems and records the resolved
   version in `Gemfile.lock`.

   ```sh
   bundle install
   ```

2. If your app doesn't already have Rails' built-in login system, add it
   first:

   ```sh
   bin/rails generate authentication
   ```

3. Add AddAuth:

   ```sh
   bin/rails generate add_auth:install
   bin/rails generate add_auth:email_link
   bin/rails db:migrate
   ```

   This adds password sign-in *and* "email me a sign-in link" as ways to log
   in, plus a page where a signed-in user can see their active sessions and
   sign out of one remotely.

4. Set these values in `config/initializers/add_auth.rb`:

   ```ruby
   AddAuth.configure do |config|
     config.base_url = "http://localhost:3000"
     config.mail_from = "AddAuth <sign-in@example.test>"
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

`add_auth:install` just writes the configuration file and runs a quick health
check -- it doesn't turn anything on by itself. `add_auth:email_link` is the
one that does the real work: it also sets up hardened sessions, adds the
sign-in routes, and creates the database tables sign-in links are stored in.
If you only want hardened sessions and don't need email sign-in yet, run
`bin/rails generate add_auth:session_upgrade` instead. It's safe to run these
generators again later -- they won't overwrite changes you've already made.

```ruby
AddAuth.configure do |config|
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
bin/rails add_auth:deliver_pending
```

It retries pending sign-in emails and erases expired delivery ciphertext. Keep an eye on failed background jobs -- a stuck one
means an email that never went out.

If a mail callback or interceptor intentionally cancels a message, AddAuth
cancels that link too and emits `delivery_cancelled.add_auth` with its issuance
ID. The sweep will not resend cancelled mail. Transport failures remain retryable;
keep delivery errors enabled so failures can be detected.

Run `bin/rails add_auth:doctor` any time after changing configuration. It
double-checks your migrations, your `base_url`, your mail and background-job
setup, and your CAPTCHA setup (if you turned one on), and tells you exactly
what's missing. It also checks enabled passkey, reauthentication, recovery,
notification and ejection wiring. Verify your host integrations using the
[deployment checklist](https://addauthgem.com/production/).

Visit `/sign-in` to sign in with a password, or to request an email link
instead when email is enabled. Clicking the emailed link opens a confirmation page -- you still
have to click a button there to actually sign in. That extra click matters:
it stops email scanners and link-preview bots from signing you in just by
opening your inbox. The original `/session/new` and every route to `SessionsController#create`
use the same protected sign-in flow. The host controller file is preserved, but
its `new`/`create` actions are handled by AddAuth once session adoption is enabled.
Move custom sign-in presentation into AddAuth's ejected views and verify custom
controller hooks before adoption. Password reset remains owned by Rails. Changing a password or email address automatically signs
out other sessions and cancels any pending sign-in links, as long as the
change goes through Rails and not a direct database update.
Password and address changes cancel existing email links even while email sign-in
is temporarily disabled.
For email/passkey-only sign-in, set `config.passwords_enabled = false` in the
initializer and restart. Password verification and password proof are rejected;
the shared sign-in page hides password controls. Existing `SessionsController`
aliases stay guarded. A host that removes that controller owns its replacement
routes. Review Rails' password-reset routes separately: AddAuth does not replace
account provisioning or password reset. Keep the conventional `User`/`Session`
models, Rails email normalization and one authentication database connection pool.

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

Session management uses up to 50 candidates per page, with the current browser
pinned on the first page and older pages ordered by session creation ID.
`Core::Sessions#list` returns the first page; hosts building custom lists use
`list_page(user:, current_session_id:, before:)` and its `entries`/`next_cursor`.
Cursors do not authorize access to another account.

## Rate limits and maintenance

Configure these operating limits and scheduled tasks for your app:

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
- Schedule `bin/rails add_auth:deliver_pending` every minute with the same
  configuration and shared cache as the web processes. It removes expired
  ceremonies and records completion using the cache's read/write operations.
  In production, `bin/rails add_auth:doctor`
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

## Block bots with a CAPTCHA (optional)

AddAuth can show a Cloudflare Turnstile or Google reCAPTCHA check before
someone can sign in or request an email link. This is entirely optional --
skip it if you don't need it yet.

1. Sign up for Turnstile or reCAPTCHA (whichever you'd rather use) and get a
   site key and a secret key from them.
2. Run one command:

   ```sh
   bin/rails generate add_auth:challenge turnstile
   # or, for reCAPTCHA:
   bin/rails generate add_auth:challenge recaptcha --version=v2
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
AddAuth's default is to block sign-in rather than let everyone through
unchecked. If you'd rather let people sign in during that kind of outage than
lock everyone out, set `config.challenge_when_unavailable = :open` in
`config/initializers/add_auth.rb`.

## Change how long sessions and links last (optional)

AddAuth ships with sensible defaults, but you can adjust them:

- A signed-in session lasts **12 hours**, or **30 minutes of no activity**,
  whichever comes first.
- An emailed sign-in link stays valid for **20 minutes**.

To change any of these, edit `config/initializers/add_auth.rb`:

```ruby
AddAuth.configure do |config|
  config.session.lifetime = 24.hours              # how long a session lasts, total
  config.session.idle_timeout = 1.hour             # how long before inactivity signs someone out
  config.email_link.token_lifetime = 10.minutes    # how long an emailed link stays clickable
end
```

There's no need to touch these unless your app has specific requirements --
the defaults follow common security guidance.

## Style the login pages

The default CSS uses scoped `add_auth-*` classes and `--add_auth-*` properties.
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
AddAuth does not install either framework. Verify contrast/focus in your theme.

Set `config.stylesheet = nil` to render without a stylesheet. To own the markup,
run `bin/rails generate add_auth:views --only=email_link` or
`bin/rails generate add_auth:views --only=sessions`; customize the copied
partials and dedicated layout, keeping form actions, CSRF fields, cache directives
and secret-free assets. Prefer class overrides when markup can stay shared.
See the ejection and upgrade instructions below.

## Browser-bound email and reauthentication

Ordinary email links work across devices by default. After running the current
`add_auth:email_link` generator and its additive migration, set
`config.email_link.same_browser = true` to require the requesting browser. A
wrong-browser attempt does not consume the link. Existing bound links stay bound
when the option is disabled; enabling it rejects outstanding unbound links.
Do not roll back to a reader that ignores browser binding while bound links live.

Run `bin/rails generate add_auth:step_up` and `bin/rails db:migrate` to install
password and email reauthentication, including the session/email prerequisites.
Declare the purposes your host exposes:

```ruby
AddAuth.configure do |config|
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
`AddAuth::Result`. Perform your resource ownership, authorization and target/version
checks inside that database block; do not make network calls while it holds the
account lock. It must own the transaction and cannot run inside an outer one.
The authentication proof is reusable for the configured freshness window; the
host owns single-use business confirmation and idempotency. Reset, revocation,
expiry and credential changes invalidate the appropriate evidence. An unknown
purpose or unavailable required method denies access.

`bin/rails generate add_auth:views --only=step_up` ejects the shared templates.
Passkey-only purposes require verified browser user verification. A method label
or recent password/email timestamp cannot satisfy that requirement.


## Passkeys, recovery and security mail

Run the feature generator and review its additive migrations before enabling traffic:

```sh
bin/rails generate add_auth:passkeys
bin/rails db:migrate
```

It installs the session, email, step-up and notification prerequisites. Configure
stable deployment identity and your host's verified recovery address explicitly:

```ruby
AddAuth.configure do |config|
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
remaining passkey or the host's documented support process; AddAuth does not
supply recovery codes. Keep strict enforcement installed during maintenance and
rollback.

`sign_out_everywhere` also accepts the configured allowed verification methods.
A successful proof returns to a separate confirmation page; it does not replay
the sign-out request. Hosts may declare their own purposes using the same API.

`add_auth:notifications` can also be installed independently with hardened
sessions. It sends notices for password/address changes, credential addition or
removal, policy changes and completed recovery. Address changes notify both old
and new addresses. Notifications use an encrypted durable outbox and the same
lease/retry/cancellation machinery as sign-in mail; they contain no secret links.
Schedule `bin/rails add_auth:deliver_pending` at least every minute for interrupted
queue handoffs, retries and expired-secret cleanup. Ambiguous transport failures
can duplicate the same message; they do not create a new authentication proof.
Keep Action Mailer's delivery errors enabled.

All account, session, credential, ceremony, email-proof and notification tables
must use the same database connection pool. Cross-database authentication writes
are rejected. SQLite and PostgreSQL have real-store concurrency coverage; other
adapters need their own contracts before adoption.

## Ejection and upgrades

```sh
bin/rails generate add_auth:views
bin/rails generate add_auth:controllers
bin/rails generate add_auth:javascript
bin/rails generate add_auth:mailer_views
bin/rails add_auth:doctor
```

Generators preserve existing files. New copies carry a version/source fingerprint;
`config/add_auth-ejections.json` retains their pristine upstream baseline. Commit
that manifest with your host customizations. Doctor identifies customized or
missing files and prints upstream changes after a gem upgrade. Apply and review
those changes manually. To accept a reviewed upstream baseline, remove only its
reviewed file entries from the manifest and rerun the relevant ejection generator;
existing host files stay intact. Keep unreviewed entries so doctor continues to
report them. Rerunning a generator never silently advances
an old baseline or overwrites your code. Keep controller policy calls, browser
cleanup, CSRF and cache protections intact.

`add_auth:views --only=passkeys` includes management and recovery; `--only=step_up`
includes reauthentication. Ejected JavaScript lives in `app/javascript/add_auth`
and is served by the fixed asset routes. Mailers resolve host template overrides.
The same browser suite runs with engine files and with all four surfaces ejected.

For host specs, `require "add_auth/testing"` provides framework-neutral
`AddAuth::Testing.delivered_link(mail, purpose: :sign_in)` (also
`:reauthentication` and `:recovery`) and
`AddAuth::Testing.with_virtual_authenticator(selenium_driver) { |authenticator| ... }`.
The latter removes the virtual authenticator even if the block raises; install
Selenium in the host test bundle. AddAuth itself uses RSpec.

## Operations and rollback

Run doctor after migrations and template upgrades. Expand schemas before enabling
features; generators preserve existing sessions and credentials. Keep the new
reader during rollback while browser-bound proofs or strict accounts exist.
Rolling back to code that ignores their policy can restore forbidden access.
Do not drop credential/policy columns to disable a feature.

Monitor `passkey_failure.add_auth` (reason only),
`notification_enqueue_failed.add_auth` (event ID), delivery failures/cancellations
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


Disabling `config.email_link.enabled` rejects new email requests and hides the
email form while retaining hardened session reading and revocation. Expired
outbox ciphertext is scrubbed and expired WebAuthn ceremonies are deleted by
`deliver_pending`. Each pass handles at most `config.maintenance.batch_size`
rows per operation and model (default 100; range 1–1000). Configure
`maintenance.session_retention`, `maintenance.email_retention` and
`maintenance.notification_retention` as nonnegative seconds or Rails durations.
They default to `nil`, preserving history until the host chooses its retention
policy. Session retention starts at expiry or revocation; receipt retention starts
at expiry. Active delivery leases and live sessions are protected. Monitor
`maintenance.add_auth` counts and pending age: a successful bounded pass does not
mean the backlog is empty. Repeated sweeps can enqueue duplicate jobs, handled by
the existing delivery lease and delivered-state checks. Keep proxy trust configured in
Rails, test Secure/HttpOnly/SameSite cookies through your TLS terminator, and
verify atomic cache increments across every app instance. Doctor checks local
configuration and schema; it cannot prove your mail provider, proxy, cache cluster
or recovery procedures work in production.

## Scope

AddAuth 0.2 implements password/email/passkey sign-in, session
adoption and management, purpose-bound verification, passkey recovery and
strict account policy, durable security mail, and challenge adapters. Account
provisioning, address confirmation and password reset remain host responsibilities.
Release acceptance uses local real-database, generated-host, browser and
SMTP/queue/cache tests. Hosts verify their own live providers and supported
physical devices before deployment. Recovery codes and AddAuth-owned password
policy remain deferred.

## Roadmap

Track development progress in [ROADMAP.md](ROADMAP.md). Check
[release status](https://addauthgem.com/release-status/) for package availability.

## Contributing

Public issues are open for bug reports and feedback; pull requests are currently
restricted to collaborators. See the
[contributor guide](https://github.com/taimoorq/add_auth/blob/master/CONTRIBUTING.md)
for checkout setup, source layout and test commands. Report vulnerabilities
privately through [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE.txt](LICENSE.txt).
