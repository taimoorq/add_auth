# Changelog

## 0.2.0.dev — 2026-09-07 (prerelease)

First integrated development release for evaluation in Rails 8.0 and 8.1 hosts
on Ruby 3.3, 3.4 and 4.0. Production acceptance and API stabilization remain open;
see [ROADMAP.md](ROADMAP.md). The earlier `v0.1.0` tag did not publish a gem.

### Security and lifecycle hardening

- Atomically retire the browser's previous session on password/email sign-in,
  including account switches; retain it on failed proof or database rollback.
- Invalidate installed email tokens on password/address changes even while email
  sign-in is disabled, preserving hosts without email persistence.
- Recheck current account, initiating session and bearer generation under lock
  for revoke-one. Its Core API now requires the initiating `session:`.
- Treat mail callback/interceptor suppression as cancellation: revoke the link,
  emit `delivery_cancelled.latchkey` with only the issuance ID, and never mark it
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
- Add `latchkey:challenge turnstile|recaptcha` scaffolding with environment-keyed
  secrets and an idempotent fixed challenge asset route.
- Extend `latchkey:doctor` to verify session elevation columns, challenge policy
  and the reCAPTCHA v3 asset route alongside origin/mail/cache checks.
- Add view ejection, fresh-host installation tests, CSRF-enabled Chrome journeys,
  real cookie/worker failure tests and permanent default-color contrast checks.

- Add the Rails-backed email-token persistence slice: atomic replacement and
  consumption/session persistence, encrypted expiring delivery intent, replay,
  address/eligibility checks, rollback and query-cache protection.
- Add `latchkey:email_tokens` with additive schema and custom-model preservation;
  add inert configuration install and per-feature session/email generators.
- Require explicit strong HMAC key material in Core; derive Rails defaults through
  the engine and make challenge verification outcomes immutable.
- Add shared fake/SQLite contracts, host request specs, fresh Rails generator tests
  and a Ruby/Rails CI matrix. Replace generated Minitest stubs with RSpec coverage.

- Repository skeleton: two-layer architecture (`Latchkey::Core` /
  `Latchkey::Rails::Engine`), closed `Result` type, challenge adapter
  interface (`Base`/`Null`/`Test`), remaining generator stubs (`views`,
  `controllers`, `javascript`), and the `latchkey:doctor` rake task stub.
  See the canonical design in the companion workspace.
