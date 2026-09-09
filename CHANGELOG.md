# Changelog

## 0.3.0 — 2026-09-09

Optional account lifecycle, bounded Devise migration and native authentication.
The standard Rails-generator installation remains supported; enable only the
additional capabilities your host needs. The latest-0.x support policy continues.

- Add read-only Devise inventory, additive account preparation, explicit legacy
  password adoption and retired-source write fences. Preserve account IDs and
  reject ambiguous identifier/credential conversions.
- Add optional registration, confirmation/reconfirmation, reset, lock/unlock,
  account changes and remembered sessions with shared Core policy and delivery.
- Integrate maintained provider libraries without owning their registrations,
  protocol exchange, unrelated routes or provider API credentials. Preserve
  identity ownership and require independent enrollment confirmation.
- Add opt-in finite native sessions, account-scoped revocation, S256-bound
  single-use browser handoffs and optional nonce-bound Apple token verification.
  Mobile duration settings are separate from browser settings; refresh-token
  families are not part of this finite profile.
- Verify generated/ejected pages with Turbo, ordinary JavaScript without Turbo
  and permitted no-JS. Add populated migration, checkpoint, compatibility
  rollback, provider and native integration fixtures.

## 0.2.2 — 2026-09-08

- Reject Solid Cache as an authentication rate-limit store: simultaneous first
  increments can be lost. Runtime fails closed and doctor explains how to
  configure a separate atomic store. Solid Queue and ordinary application
  caching remain independent choices. No schema, cookie or job-format change.
- Add checksum-pinned upgrades from the published 0.2.1 package to the candidate
  and back, including persisted authority, pending delivery and customized
  ejections; run this acceptance on every supported Ruby/Rails CI combination.
- Verify Solid Queue with a separate queue database, demonstrate Solid Cache
  counter unsuitability on PostgreSQL, and measure bounded maintenance.
- Refresh immutable checkout action pins to 7.0.1 and add upgrade/compatibility
  guidance. See the upgrade guide before changing a deployed bundle.

## 0.2.1 — 2026-09-07

- Install release dependencies into RubyGems' normal gem path so the attestation
  preload and Bundler resolve the same OpenSSL version. Check that loading order
  before requesting publishing credentials. Retain OIDC and attestations.
- The immutable `v0.2.0` tag passed all acceptance checks but did not publish a
  package because its release action hit an OpenSSL activation conflict.
  Authentication runtime and feature behavior are unchanged from that candidate.

## 0.2.0 — 2026-09-07

First integrated 0.2 release for Rails 8.0 and 8.1 hosts on Ruby 3.3, 3.4 and
4.0. Local integration acceptance covers real stores, generated hosts, browser
journeys and SMTP/queue/cache recovery. Hosts own verification of their production
providers and physical devices. Review generated changes when upgrading this
pre-1.0 API. The earlier `v0.1.0` tag did not publish a gem.

### AddAuth name

- Rename the development gem from Latchkey to `add_auth`, with Ruby namespace
  `AddAuth` and `add_auth:*` generators/tasks. Standard Rails/Thor naming handles engine loading, models, controllers and
  generator discovery without an inflection override.
- Fresh installations use AddAuth tables, configuration, cookies, cryptographic
  contexts, jobs and ejection manifests. This release does not migrate an
  existing Latchkey installation or provide a legacy namespace alias.

### Operations and documentation

- Bound session pages to 50 candidates plus the current browser and one lookahead,
  using account-scoped creation-order cursors. Add session lookup/retention indexes.
- Bound each maintenance operation to 100 rows by default (configurable 1–1000).
  Add opt-in session and email/notification receipt retention. Recheck eligibility
  during cleanup, protect active delivery leases and report completed-pass counts.
- Check standalone notification queue/mail configuration and successful cleanup
  in doctor; fail the sweep if the queue declines a handoff.
- Add local Redis/Sidekiq/SMTP restart and retry acceptance without runtime
  dependencies on those services.
- Expand the RubyGems-first manual with passkeys, reauthentication, recovery,
  notifications, testing and operations guides, highlighted code and accessible
  Mermaid diagrams. Email themes remain an optional host presentation choice.

### Security and lifecycle hardening

- Prevent fixed-window rate-limit bursts and cap anonymous passkey ceremonies;
  require production doctor to observe a recent successful cleanup run.
- Return an unavailable response for invalid passkey configuration and safely
  redirect when a step-up purpose is removed during a request.
- Keep generated-host Gemfiles and lockfiles isolated under Bundler 4, and serve
  public assets through a stateless controller restricted to GET/HEAD.
- Atomically retire the browser's previous session on password/email sign-in,
  including account switches; retain it on failed proof or database rollback.
- Invalidate installed email tokens on password/address changes even while email
  sign-in is disabled, preserving hosts without email persistence.
- Recheck current account, initiating session and bearer generation under lock
  for revoke-one. Its Core API now requires the initiating `session:`.
- Treat mail callback/interceptor suppression as cancellation: revoke the link,
  emit `delivery_cancelled.add_auth` with only the issuance ID, and never mark it
  delivered or resend it. Actual delivery errors retain the same-intent retry.
- Apply shared abuse/CSRF/challenge policy to legacy and new password entry
  points; throttle and lock password reauthentication for revoke-all.
- Bind step-up to proof time, current credentials and bearer generation, and
  recheck authority under the transaction lock. Require transaction-owned email
  session creation, including connection/thread provenance.
- Redact provider tokens/secrets; classify outages accurately and bound provider
  payloads, scores, network deadlines and response sizes.
- Use scoped Stimulus widgets with Turbo retry/cache cleanup, shared session-only
  assets, HTML/stream reauthentication errors and correct frame/redirect behavior.
- Fail closed on missing production captcha configuration; expand doctor and
  packaged-host/README tests. Pin release actions, require tested tag provenance
  and add PostgreSQL CI plus the Ruby 4.0/PostgreSQL branch checks.
### Authentication features and host integration

- Add explicit email/passkey-only mode, rejecting password proof while keeping
  installed Rails password aliases guarded. Support a User without password
  methods during email-address invalidation. Default password behavior is unchanged.
- Require authenticated sessions on account-management endpoints even in hosts
  whose general page guard permits anonymous readers; retain public proof routes.
- Add optional browser-bound ordinary email links and public password/email/passkey
  reauthentication, always binding email elevation to its browser/session/purpose.
- Add discoverable passkey enrollment, explicit/conditional sign-in, management,
  UV and exact RP/origin enforcement, atomic counters and last-credential checks.
- Add trusted-address recovery with replacement grants and opt-in strict policy
  enforced across sign-in, reset, fallback, feature toggles and policy changes.
- Add encrypted security-notification intents sharing email delivery leases,
  retries, cancellation and the pending-delivery/expired-ceremony sweep.
- Add complete view/controller/JavaScript/mailer-view ejection, preserved source
  fingerprints, doctor upstream diffs and framework-neutral browser/mail helpers.
- Require WebAuthn 3.4.3 or newer in the 3.x line and Public Suffix 7.x for the
  verified ceremony API and RP public-suffix validation; Ruby/Rails floors stay.

- Add the signed-ID session bridge, random bearer cookies, absolute/idle expiry,
  revocation, safe return paths and host password/address invalidation hooks.
- Add authenticated session visibility and revoke-one management at `/sessions`;
  metadata excludes bearer material and ownership is checked under the account lock.
- Add password-reauthenticated `/sessions/revoke-all`, which revokes every active
  bearer under the account lock and clears the initiating browser.
- Add the Rails-independent step-up policy foundation: purpose-bound grants,
  separate freshness/strength windows, session/account binding and passkey UV
  enforcement, persisted evidence, atomic bearer rotation and host mutation guards.
- Complete the default email sign-in path with encrypted request jobs, idempotent
  issuance, leased delivery retries, recovery sweep, inert link confirmation and
  deliberate account switching. Keep public request responses generic.
- Add shared HTML/Turbo login pages, no-JS password/email flows, scoped CSS and
  semantic class/stylesheet overrides for host Bootstrap and Tailwind builds.
- Add server-backed Turnstile and reCAPTCHA v2/v3 challenge adapters with
  hostname/action/score checks, bounded HTTPS verification, explicit closed/open
  outage policy, provider markup and a Turbo-safe reCAPTCHA v3 submit bridge.
- Add `add_auth:challenge turnstile|recaptcha` scaffolding with environment-keyed
  secrets and an idempotent fixed challenge asset route.
- Extend `add_auth:doctor` to verify session elevation columns, challenge policy
  and the reCAPTCHA v3 asset route alongside origin/mail/cache checks.
- Add view ejection, fresh-host installation tests, CSRF-enabled Chrome journeys,
  real cookie/worker failure tests and permanent default-color contrast checks.

- Add the Rails-backed email-token persistence slice: atomic replacement and
  consumption/session persistence, encrypted expiring delivery intent, replay,
  address/eligibility checks, rollback and query-cache protection.
- Add `add_auth:email_tokens` with additive schema and custom-model preservation;
  add inert configuration install and per-feature session/email generators.
- Require explicit strong HMAC key material in Core; derive Rails defaults through
  the engine and make challenge verification outcomes immutable.
- Add shared fake/SQLite contracts, host request specs, fresh Rails generator tests
  and a Ruby/Rails CI matrix. Replace generated Minitest stubs with RSpec coverage.
