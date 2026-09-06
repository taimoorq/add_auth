# Roadmap

Latchkey extends the output of `bin/rails generate authentication` (Rails 8)
with passwordless email-link sign-in, WebAuthn passkeys, step-up sessions,
pluggable challenge (Turnstile/reCAPTCHA) support, and ejectable
Hotwire/Turbo/Stimulus views that also work with no JavaScript at all.

This roadmap tracks the v1 scope decided in the design doc's [§14 Scope
decision and roadmap](https://github.com/taimoorq/latchkey-workspace) (private
planning repo — see `AGENTS.md` in this repo for how the two repos relate).
Check items off here as they land; this file is the public, incremental view
of that plan, not a duplicate of it.

Every item must satisfy the guardrails in `AGENTS.md` before it's checked off:
tested with RSpec, DRY, and — for anything user-facing — working identically
with and without JavaScript (see "Definition of done" there).

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
      `AGENTS.md`.
- [x] RubyGems release via [Trusted
      Publishing](https://guides.rubygems.org/trusted-publishing/) (OIDC from
      GitHub Actions) instead of a long-lived API key, gated behind
      `rubygems_mfa_required` and `allowed_push_host`.
- [x] `bin/setup` / `bin/console` dev scripts.
- [ ] First tagged release (`v0.1.0`) published via the Trusted Publishing
      workflow, to lock in the gem name on RubyGems.

## 1. Core primitives

- [x] `Latchkey::Result` — closed success/failure type for auth outcomes.
- [x] `Latchkey::Configuration` / `Latchkey.configure`.
- [x] Challenge adapter contract (`Latchkey::Core::Challenge::Base`) with the
      three-state result (success / rejected / unavailable).
- [x] `Challenge::Null` (default, always succeeds) and `Challenge::Test`
      (configurable, for specs) adapters.
- [ ] `Challenge::Turnstile` adapter.
- [ ] `Challenge::Recaptcha` adapter.
- [ ] Pluggable password-hashing adapter point (bcrypt default via
      `has_secure_password`; `Argon2` override) — see the cryptography policy
      in the design doc's §2. Only load-bearing once v2 password registration
      ships; tracked here so the seam exists before it's needed.
- [ ] Pluggable session/sign-in-token digest adapter (HMAC-SHA256 via
      `Rails.application.key_generator` by default; override point for
      FIPS/HSM-constrained hosts).

## 2. Adopting the generator's `Session` model

This is the step that makes "plugs into the generator" a real claim, and the
design doc calls it out as the first thing to prototype — later items depend
on it.

- [ ] `latchkey:install` migration that extends the existing `Session` table
      in place: adds `authenticated_with`, `elevated_at`, `expires_at`,
      `last_seen_at`, `revoked_at`.
- [ ] Backfill: HMAC-digest each existing plaintext session token, write
      `token_digest`, then drop the plaintext column — without signing
      anybody out.
- [ ] Spec coverage proving pre-upgrade sessions survive the migration.

## 3. Email-link sign-in

- [ ] `Latchkey::Core::Strategies::EmailLink#issue` — token issuance via
      `generates_token_for`, dual-key rate limiting (IP + hashed identifier).
- [ ] `#consume` — POST-to-consume (not GET), enumeration-safe responses.
- [ ] Mailer + generated view for "check your email".
- [ ] Generated controller actions and routes.

## 4. Passkeys

- [ ] `Latchkey::Core::Strategies::Passkey#registration_options` /
      `#register` — registration ceremony, opaque `webauthn_id` (never PK or
      email).
- [ ] `#authentication_options` / `#authenticate` — discoverable
      (usernameless) sign-in.
- [ ] Conditional UI / autofill (`mediation: "conditional"`) wired into the
      generated sign-in form's Stimulus controller.
- [ ] Sign-counter clone-detection handling (accept 0 unconditionally; flag
      only a decreasing non-zero count).
- [ ] Generated "create a passkey" flow from an authenticated session.

## 5. Step-up (elevated) sessions

- [ ] `authenticated_with` / `elevated_at` read/write helpers on `Current`.
- [ ] Controller concern for requiring a fresh re-authentication before a
      sensitive action.
- [ ] Generated re-authentication prompt (passkey or email link).

## 6. Generators and the exit door

- [ ] `latchkey:install` — wires the engine, runs the Session migration.
- [ ] `latchkey:views` — copies ejectable views into the host app.
- [ ] `latchkey:controllers` — copies ejectable controllers.
- [ ] `latchkey:javascript` — copies Stimulus controllers, wires importmap
      or jsbundling as appropriate.
- [ ] `latchkey:challenge` — installs a chosen Challenge adapter's
      config/keys scaffolding.
- [ ] `latchkey:doctor` rake task — checks the host app's setup against the
      current generator output and flags drift (see `lib/tasks/latchkey.rake`
      for the stubbed checklist).

## 7. Hotwire, Turbo, and no-JS parity

- [ ] Every generated form/flow works with Turbo Streams/Frames.
- [ ] Every generated form/flow works with JavaScript fully disabled
      (progressive enhancement, not a JS-only path).
- [ ] Passkey conditional UI degrades to an explicit "Sign in with a passkey"
      button when autofill isn't available.

## 8. Testing

- [ ] Virtual-authenticator test helpers for passkeys (the untestability gap
      this design doc identifies as the actual blocker on passkey adoption
      elsewhere in the Rails ecosystem).
- [ ] Shared RSpec examples for each strategy (email link, passkey, step-up).
- [ ] Request specs for every generated controller/route, run against a
      dummy app.

## 9. Release readiness

- [ ] README rewritten from "pre-implementation skeleton" to real usage docs.
- [ ] CHANGELOG entries per release, Keep-a-Changelog style.
- [ ] `v1.0.0` tagged once the above is complete and dogfooded.

## v2 (decided with usage data after v1 ships)

Not started, and not committed to — reassessed once v1 has real adopters, per
the design doc's §14. In the priority order that section lays out:

- [ ] Password registration and reset (Devise parity).
- [ ] Confirmable (email confirmation).
- [ ] Lockable and validatable (Devise parity).
- [ ] Recovery codes for passkey-only users who lose every device (the
      design doc's leading open question — see below).
- [ ] Multiple realms / routing scopes (the routing DSL already accepts a
      scope argument so this isn't a breaking change when it lands).

## Open questions to resolve before they're load-bearing

Tracked in full in the design doc's §14; summarized here so they aren't lost:

- [ ] Account recovery for passkey-only users (leaning: opt-in recovery
      codes after v1; email link remains the default recovery path).
- [ ] Whether `Latchkey::Core` should depend on a narrow set of duck-typed
      methods or a full repository interface, to keep non-Active-Record hosts
      possible without adding indirection everywhere.
- [ ] Whether API/token authentication becomes a sibling gem or a
      `Latchkey::ApiTokens` module (out of v1 scope either way).
- [ ] A configurable base class for Latchkey's own models, so extraction into
      a two-database host application doesn't become a breaking change later.

## Worth shipping standalone regardless of the gem's adoption

Called out explicitly in the design doc because they don't depend on the rest
of Latchkey finding an audience:

- [ ] Virtual-authenticator test helpers, as their own small library.
- [ ] The Challenge adapter's three-state result, as its own small library.
