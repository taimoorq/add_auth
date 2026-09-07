# Roadmap

Latchkey extends Rails 8's `bin/rails generate authentication` with email-link
sign-in, passkeys, purpose-bound reauthentication, session hardening and pluggable
captcha. It reuses the host's accounts and Session model.

The canonical design lives in the companion **private** planning workspace:
[scope](https://github.com/taimoorq/latchkey-workspace/blob/master/docs/authentication-gem-plan.md#14-scope-decision-and-roadmap)
and [user journeys, contracts and test plan](https://github.com/taimoorq/latchkey-workspace/blob/master/docs/authentication-gem-plan.md#16-integrated-user-journeys-and-implementation-plan).
Those links require workspace access. This public checklist stands on its own as
progress tracking; it does not duplicate the private design. Engineering guidance
stays only in that workspace's `AGENTS.md`.

Reviewed 2026-09-07. The 0.2.0.dev prerelease source implements the v1
strategy features: password/email/passkey sign-in, hardened sessions, reauthentication,
credential management, default recovery and strict policy, security notifications,
challenge adapters and fingerprinted ejection. Core policy, session finalization
and leased mail delivery are shared by engine and ejected flows.

Local acceptance passes **279 RSpec examples plus 22 ejected-UI examples** on each
Ruby 3.3.11/3.4.8/4.0.5 × Rails 8.0.5.1/8.1.3.1 combination. Standard is clean.
PostgreSQL passes **181 store/request examples on each Rails line**. Refreshed
root and both Rails dependency audits report no known vulnerabilities. The
[canonical evidence ledger](https://github.com/taimoorq/latchkey-workspace/blob/master/docs/authentication-gem-plan.md#16-integrated-user-journeys-and-implementation-plan)
records successful commands and the failures that led to corrections. Checked
items mean passing relevant local specs; remote CI/CodeQL, live-service validation,
real-device diversity, dogfooding and release acceptance remain open.

Generated pages use shared HTML/Turbo partials. Password/email paths support
ordinary no-JS navigation when permitted by policy; passkeys require browser
JavaScript, and a configured captcha may also require it. Strict policy must never
be weakened to simulate no-JS parity.

## 0. Project foundations

- [x] Gemspec with a capability-derived Rails floor (`>= 8.0`, the release
      that shipped the authentication generator) and a security-patch-derived
      Ruby floor (`>= 3.3.0`), not just whatever the newest Rails tolerates.
- [x] MIT license, Code of Conduct, Security policy (`SECURITY.md`).
- [x] RSpec test setup (`.rspec`, `spec/spec_helper.rb`).
- [x] `standard` for formatting/linting.
- [x] CI (GitHub Actions): RSpec + Standard across the Ruby support matrix,
      plus a `bundler-audit` job.
- [x] Dependabot, grouped by ecosystem, with the Rails family grouped
      together — the concrete mechanism behind the "stay current" mandate in
      the workspace's `AGENTS.md`.
- [x] RubyGems release workflow configured for [Trusted
      Publishing](https://guides.rubygems.org/trusted-publishing/) (OIDC from
      GitHub Actions) instead of a long-lived API key, gated behind
      `rubygems_mfa_required` and `allowed_push_host`.
- [x] `bin/setup` / `bin/console` dev scripts.
- [ ] First successful tagged prerelease published via the Trusted Publishing
      workflow, to lock in the gem name on RubyGems.

## 1. Core primitives

- [x] `Latchkey::Result` — closed success/failure type for auth outcomes.
- [x] `Latchkey::Configuration` / `Latchkey.configure`.
- [x] Challenge adapter contract (`Latchkey::Core::Challenge::Base`) with the
      three-state result (success / rejected / unavailable).
- [x] `Challenge::Null` (default, always succeeds) and `Challenge::Test`
      (configurable, for specs) adapters.
- [x] Purpose-separated HMAC digests with explicit strong key material,
      real Rails key derivation, override tests and a framework-free Core check.

## 2. Shared contracts and a real host harness — slices A1/A2

- [x] One Core policy for eligibility, purpose, proof strength and freshness;
      one session finalizer and public result presenter across all methods.
- [x] Ordinary email-token store and encrypted delivery-intent contracts,
      shared examples against fake and real SQLite/PostgreSQL adapters, with clock/digest
      injection, replay/race/rollback/address-binding coverage.
- [x] Passkey/recovery proof and host lifecycle contracts, with actual WebAuthn
      cryptography, rollback and concurrency on SQLite and PostgreSQL.
- [x] Boot `spec/dummy` through RSpec; replace generated test stubs with
      password sign-in/reset/sign-out requests and real database coverage.
- [x] Generate and boot Rails 8.0/8.1 hosts; exercise the persistence
      generator and preserve host customizations. CI covers both Rails lines
      on Ruby 3.3, 3.4 and 4.0. Commands are in README.
- [x] Browser/virtual-authenticator harness with the passkey slice.

## 3. Adopt the host's sessions and password flow — slice B, U1/U8

- [x] Inert `latchkey:install` configuration plus additive `session_upgrade`
      migration and shared lifecycle hooks; repeat generation preserves edits.
- [x] Bounded signed-ID cookie transition to random digested bearers, with
      real signature/tamper, race, cutoff and revocation tests.
- [x] Password/reset normalization and routes preserved; password/address
      invalidation and account deletion integrated. Hosts supply eligibility.
- [x] Absolute/idle expiry, protected cookies, fresh session IDs and safe local
      return destinations for implemented password/email flows.
- [x] Current-session sign-out revokes its bearer and clears browser state.
- [x] Session list and revoke-one, including next-request rejection in another
      browser and cache/back-safe authenticated-page handling.
- [x] Sign-out-everywhere, guarded by fresh allowed proof and covering every
      active browser, with old bearers rejected on their next request.

## 4. Complete email-link sign-in — slice C, U2

- [x] Internal `EmailLink#issue`/`#consume` lifecycle: atomic replacement and
      session persistence, one-use proof, account/address eligibility rechecks,
      expiring encrypted delivery handoff and tested concurrent use.
- [x] Wire the lifecycle to the hardened session finalizer and uniform
      asynchronous/rate-limited public intake.
- [x] Additive token model/store generator and protected pending-delivery
      payload, cleared on consumption/revocation; no Session schema changes.
- [x] Encrypted request jobs, idempotent issuance, leased mail delivery,
      retry/cleanup sweep and delivered-link-to-browser integration.
- [x] Durable security notifications share the delivery lease/retry/cancellation
      contract and recover interrupted queue handoffs.
- [ ] Deployment-specific SMTP, queue and notification monitoring validation.
- [x] Shared IP + keyed identifier rate policy, normalization and generic
      request/resend responses for unknown, disabled and throttled accounts.
- [x] Request → check-email → inert GET confirmation → explicit POST consume
      → session; masked account confirmation and deliberate account switching.
- [x] Resend limits, newest-link guidance, expired/used-link recovery and
      cross-device sign-in by default.
- [x] Optional same-browser binding, including delivered links, wrong-browser denial,
      Turbo/no-JS browsers and generated/ejected hosts.
- [x] Real DB concurrency and delivered-mail-to-session specs, plus HTML,
      Turbo and no-JS request/system coverage for the complete flow.

- [x] Basic scoped CSS, semantic class overrides for host Bootstrap/Tailwind
      builds, stylesheet opt-out and view ejection with custom-file preservation.

## 5. Reauthentication and recovery policy — slice D, U6/U7

- [x] Core purpose/freshness evaluator with account/session binding, generic
      elevation failures and passkey UV requirements.
- [x] Additive session elevation metadata and bearer-rotation finalizer for a
      previously authorized grant, now wired to public reauthentication routes.
- [x] Host reauthentication adapters persist purpose-bound grants and rotate the
      existing session's bearer after password/email/passkey verification.
- [x] Password/email reauthentication adapters share policy and presentation;
      email step-up is bound to the initiating browser/session/purpose.
- [x] Sensitive-action return goes to a safe confirmation page; final mutation
      rechecks authorization/grant/target and never automatically replays a POST.
- [x] Default email recovery with explicit recovery purpose, replacement grant,
      security notifications and post-recovery session/proof invalidation.
- [x] Stricter opt-in policy enforced across sign-in, fallback, credential
      management, password reset and policy changes; no hidden weaker route.
- [x] Tests for fresh-but-insufficient proof, wrong account/session/purpose,
      expiry, lost response, cancellation and attempted policy bypass.

## 6. Complete passkeys and credential management — slice E, U3–U7

- [x] Registration with discoverable credentials, server-enforced user
      verification and transaction binding to an existing account.
- [x] Discoverable sign-in with credential/userHandle ownership checks;
      explicit and conditional-autofill UI share the same verification path.
- [x] Native browser support for another device/security key, neutral cancel,
      understandable retry/fallback and strict-policy unavailable states.
- [x] First-passkey bootstrap and additional-passkey enrollment require
      appropriate fresh proof. The optional post-login invitation is a host product
      choice; v1 supplies the authenticated `/passkeys` entry point.
- [x] Credential list, rename, remove, notifications and atomic last-usable-method
      checks; default/strict recovery works with enrollment and lost-device flows.
- [x] Correct sign-counter anomaly/backup-flag handling, with atomic counter
      updates and tests for zero, equal, increasing and decreasing counters.
- [x] Exact origin/RP policy, single-use server transactions, one shared codec,
      payload bounds and cleanup of pending browser ceremonies.
- [x] Virtual-authenticator and real-store coverage of success, UV/signature/
      origin/ownership failures, replay, races, management and recovery.

## 7. Challenge adapters and accessible failure paths — slice F, U9

- [x] Turnstile adapter with hostname/action checks, provider-owned lifetime,
      bounded HTTPS timeouts and safe no-retry handling for single-use tokens.
- [x] reCAPTCHA v2/v3 adapters respecting their different verification fields
      and configured score/action requirements where applicable.
- [x] Shared success/rejected/unavailable behavior, fail-closed default and
      observable explicit fail-open policy; no implicit bypass without JS.
- [x] Retry/outage messages, preserved input, provider protocol fixtures and no
      live-provider dependency in routine specs.
- [ ] Full focus/keyboard/status accessibility audit and provider-backed browser
      interoperability after ejection.

## 8. Generators, ejection and integrated acceptance — slice G

- [x] `latchkey:install` writes inert configuration; session/email feature
      generators add reviewable wiring and preserve edits on repeat runs.
- [x] `latchkey:views`, `latchkey:controllers`, `latchkey:javascript` and
      `latchkey:mailer_views` reuse the same Core policy, presenter and templates.
- [x] `latchkey:challenge` writes environment-keyed Turnstile/reCAPTCHA config,
      adds the fixed challenge route and preserves an existing initializer.
- [x] `latchkey:doctor` checks deployment origins, cookies/session metadata,
      delivery, migrations and challenge policy/routes.
- [x] `latchkey:doctor` checks recovery policy and generated-file drift.
- [x] Every generated flow exercised before and after ejection, with Turbo
      Drive/Frames/Streams, ordinary HTML, no-JS alternatives and strict denial.
- [x] Auth-page cache/referrer protections, redacted app/job telemetry,
      CSRF, safe redirects and correct success/failure HTTP contracts.
- [x] RSpec strategy/store shared examples and host-facing test helpers,
      including virtual authenticator lifecycle and delivered-link extraction.
- [x] Full RSpec, Standard and dependency audit pass on supported local matrices;
      README/roadmap distinguish working development APIs from release gates.
- [ ] Exact-commit remote CI/CodeQL and required repository security checks;
      refresh deployed public documentation when the gem is released.

## 9. Release readiness

- [x] README rewritten from skeleton status to verified usage and migration
      instructions, linking to maintained public API docs as they ship.
- [x] Security policy updated for shipped strategies, recovery limits and
      supported versions; redacted events and incident/rollback guidance documented.
- [ ] CHANGELOG entries and successful Trusted Publishing release; a tag or
      configured workflow alone does not prove the gem was published.
- [ ] Dogfood all enabled journeys and record operational defaults, delivery
      reliability, expiry behavior and migration rollback evidence.
- [ ] `v1.0.0` only after the integrated acceptance gates pass.

## v2 — reassess after v1 usage

- [ ] Latchkey-owned password registration/reset, confirmation, lockout and
      password policy. Existing host password integration is part of v1.
- [ ] Password-hashing adapter seam, following the canonical cryptography
      policy and Rails support available at implementation time.
- [ ] Recovery codes; they are not an implied fallback for v1 strict policy.
- [ ] Multiple realms/routing scopes.

## Decisions before they become dependencies

Owner and deadline details remain in the canonical plan's section 16.

- [ ] Stabilize the public API before a stable release. The implemented runtime
      uses Rails-generator User/Session conventions; authentication models must
      share one database connection pool and cross-pool writes are rejected.
- [ ] Validate lifetime, resend, retention, key rotation and legacy-bridge
      defaults before the first adopter enables the affected flow.
- [x] Framework-neutral mail and virtual-authenticator helpers; no
      Minitest-specific integration DSL. Latchkey's own suite stays RSpec.
- [ ] Revisit API/token authentication after v1; outside current scope.

## Potential standalone libraries

- [ ] Virtual-authenticator test helpers.
- [ ] Challenge adapter contract and its three-state result.
