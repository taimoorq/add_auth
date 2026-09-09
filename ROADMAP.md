# Roadmap

AddAuth extends Rails 8's authentication generator with email-link sign-in,
passkeys, purpose-bound reauthentication, hardened sessions and pluggable captcha.
It reuses the host's accounts and Session model.

**Reviewed 2026-09-09: 0.2.2 is published, and the planned v1 strategy features
have shipped.** The bounded Devise migration and native additions below are locally verified
and selected for 0.3.0. The future 1.0 support commitment remains separate. Milestones below describe priorities, not promised dates or
versions. See [release status](https://addauthgem.com/release-status/),
[the changelog](CHANGELOG.md) and [the manual](https://addauthgem.com/).

**[0.2.2 is published and verified](https://github.com/taimoorq/add_auth/releases/tag/v0.2.2).**
It contains the counter-store correction and upgrade/operations coverage below.
The registry package passes fresh-host installation and the matching manual is
live. The owner selected this patch before accepting the proposed 1.0 commitment.

An unchecked item is remaining work; deferred candidates need a scope decision
before implementation. Checked features have passing relevant acceptance specs.
Other completed work requires its applicable verification evidence. Checkmarks
can describe tested local work; release/publication remains a separate gate. Detailed
design and decision records remain in the companion private planning workspace;
this public checklist is derived from its section 14 and stands on its own.

## Now — maintain 0.2 and learn from adoption

- [x] **R1 · Resolve the outstanding dependency update.**
      [PR #9](https://github.com/taimoorq/add_auth/pull/9) updates the immutable
      checkout pin to 7.0.1 with current required checks passing. Old Dependabot
      PR #1 is closed as superseded. All merge/release protections remain in force.
- [x] **R1 · Complete the 2026-09-07 currency review.** Review Rails/Ruby support,
      authentication APIs, WebAuthn, advisories and the competitive landscape
      before the next version bump; repeat the standing review at least quarterly.
      Floors remain Ruby 3.3 / Rails 8.0; current audits are clear. Follow Rails-
      native password hashing when the supported API permits it. Future reviews
      remain an ongoing maintenance responsibility.
- [x] **R2 · Complete a bounded first-adopter feedback review.** Official-package
      local integration already passes. Collect installation, sign-in/recovery,
      customization and operational friction; give each finding a gem fix,
      documentation improvement, host-owned resolution or explicit deferral.
      The review dispositions existing passwordless/management fixes, host-owned
      onboarding/roles/mail branding and the new upgrade/operations guidance.
      Stock and synthetic host regressions remain required for reusable changes.
- [x] **R2 · Improve onboarding from observed friction.** Update existing
      quickstart, doctor and troubleshooting guidance with exact prerequisites,
      observable success and recovery steps. Keep the public manual tied to the
      published package. Upgrade, compatibility, cache and ejection guidance is
      published for 0.2.2; build, browser and live deployment checks pass.

The exact 0.2.2 release commit passed the full CI matrix and CodeQL. The post-publication
passwordless-fixture isolation failure is fixed in
[PR #8](https://github.com/taimoorq/add_auth/pull/8); it is not an open runtime
defect or a reason by itself to republish 0.2.1.

## Next — prove upgrades, plan migrations and define the 1.0 contract

- [x] **R3 · Rehearse an upgrade from published 0.2.1.** Start with a populated
      host, active sessions, passkeys, strict accounts, pending mail and customized
      ejected files. Upgrade to the candidate and verify data/policy preservation,
      migration repeatability, doctor diffs, reviewed baseline acceptance,
      worker compatibility and safe rollback or explicit revocation. Keep
      fresh-install and before/after-ejection coverage. The checksum-pinned
      baseline/candidate/rollback test passes on all six Ruby/Rails combinations;
      CI now includes the same rehearsal.
- [x] **R4 · Validate the Rails-default operations path.** Exercise Solid Queue
      restart/enqueue failure and same-intent mail retry locally. Determine
      whether Solid Cache meets atomic rate-limit increment/TTL requirements;
      document a tested separate store if needed. Publish only verified adapter
      support. Solid Queue 1.7.0 passes with a separate queue database. Solid
      Cache 1.0.10 loses concurrent first increments on PostgreSQL; 0.2.2
      rejects it for abuse counters and documents a separate Redis store.
- [x] **R4 · Measure bounded maintenance and recovery.** Record workload,
      query counts, backlog drain and latency for session pages, outbox retries
      and cleanup. Use those measurements to explain batch sizing, retention,
      alerts and recovery procedures. SQLite/PostgreSQL rehearsals retain 5,000
      live sessions while draining 1,200 expired rows in twelve batches of 100;
      session listing uses two SELECTs and at most 52 loaded Session records.
- [x] **R5 · Inventory the proposed stable public surface.** Name supported configuration,
      Core/host hooks and Results, routes, generators/ejection metadata, testing
      helpers and redacted events. Distinguish internal APIs and document
      compatibility, deprecation and migration rules. The current integration
      reference is published; the proposed 1.0 contract remains for owner
      review under the separate item below.
- [ ] **R5 · Set the 1.0 support policy.** Specify supported runtime/database
      combinations and security-supported release lines. Publish an upgrade
      guide and evidence-backed troubleshooting updates before the candidate
      freezes. The current latest-0.x policy remains in
      [SECURITY.md](SECURITY.md).
- [x] **R8 · Define Devise migration readiness.** Inventory source versions,
      modules, extensions and customizations; provide a read-only preflight with
      supported mappings, prerequisites and actionable blockers. Running Rails 8
      alone does not establish the authentication contracts AddAuth needs.
- [x] **R8 · Provide a path for Rails-aligned Devise apps.** Reuse verified
      account/session contracts and preserve host customizations while replacing
      remaining Devise authentication wiring. Prove password compatibility,
      account restrictions, session/token revocation and safe cutover/rollback.
- [x] **R8 · Provide a path for standard or customized Devise apps.** Guide an
      additive conversion from existing models, identifiers, password storage
      and controllers to the supported Rails contracts. Preserve account IDs and
      associations; resolve incompatible hashes, identifier collisions and
      unsupported module policies before cutover. Include older-runtime
      prerequisites and host-owned lifecycle replacements where needed.
- [x] **R8 · Add optional account lifecycle support.** Registration,
      confirmation/reconfirmation, password reset, lock/unlock and account
      changes must preserve ownership, account policy and session revocation.
- [x] **R8 · Preserve provider sign-in through maintained libraries.** Add
      optional OmniAuth integration with verified identity binding, explicit
      linking/unlinking and usable recovery for provider-only accounts.
      Preserve host-owned OAuth configuration, routes and other provider flows;
      delegate protocol work to the selected libraries.
- [x] **R8 · Rehearse both migration paths and draft the guides.** Test populated Devise
      hosts before and after migration, including custom schema, peppered
      passwords, denied accounts, interrupted conversion and rollback. Verify
      supported database/runtime, ordinary HTML with JavaScript and Turbo absent,
      Turbo enhancement and permitted no-JS journeys. Draft step-by-step guides
      and prove the destination works with Devise removed.
- [ ] **R8 · Publish migration and native guides with the feature release.**
      Verify the released package, installation commands, HTTPS and deep links;
      keep development guides explicitly unpublished until then.

Local development has verified preflight, optional account lifecycle and
provider-library integration across the supported Ruby/Rails matrix, including
ordinary HTML, Turbo and permitted no-JS journeys. These additions are
unpublished. Migration/checkpoint/compatible-rollback tests and native client
acceptance are complete locally. The full adopter suite passes 1,330 examples
with zero failures and three existing empty scaffold examples pending. Six
development guides pass build, browser, keyboard and no-JS checks. Publication
and the proposed 1.0 commitment remain separate gates.

## Locally verified — Android and iOS login

Mobile support is now part of the active migration implementation. It is not available in the published gem. These capabilities extend the
same account and session policies. The verified finite profile uses explicit
30-day absolute and 14-day idle limits, with fresh sign-in after expiry. Renewable
refresh-token families remain a distinct optional capability, currently disabled.
The owner selected 0.3.0; publication and package verification remain pending.

- [x] **R8 · Password and provider login for native clients.** Return credentials
      over authenticated HTTPS responses; preserve supported client contracts.
- [x] **R8 · Secure browser-to-app sign-in handoffs.** Short-lived, single-use
      codes bound to state and a verifier, exact callback validation, and native
      Apple nonce verification; no reusable bearer tokens in callback URLs.
- [x] **R8 · Device sessions and revocation.** Expiring, digested API credentials,
      cookie/bearer separation, device listing, current-device and all-device
      logout, and invalidation on password/account changes. Evaluate optional
      renewal with rotation and replay detection as a distinct profile.
- [x] **R8 · Android/iOS migration acceptance.** Test secure client storage,
      cancellation/restarts, account switching, expiry and concurrent handoffs,
      plus supported old/new client combinations. Android/iOS consumers also
      pass against an installed gem in an isolated Rails adopter over local HTTPS.

Each change owns its tests and keeps intermediate releases usable. R3/R4 findings
feed R5. A patch may address compatible corrections; another 0.x minor is possible
if integration contracts change. A 0.3 release is not a prerequisite for 1.0.
R8 follows the published 0.2.2 correction; its supported source profiles
are bounded to the verified Devise 5.0.4 fixtures. The selected delivery version is 0.3.0. Its pre-1.0 integration contracts
remain subject to review before R5 freezes. Devise migration support is not available yet.

## Delivery — 0.3.0 feature release, then the proposed 1.0 gate

- [x] Select 0.3.0 for the locally verified migration, lifecycle, provider and native scope.
- [ ] Pass required PR and exact default-branch CI/CodeQL for 0.3.0.
- [ ] Publish 0.3.0 through protected OIDC and verify the downloaded package and manual.

- [x] **R6 · Deliver the 0.2.2 correction.**
      [PR #10](https://github.com/taimoorq/add_auth/pull/10) passed all required
      checks, followed by exact default-branch CI and protected OIDC publication.
      The downloaded package checksum and all 121 files match the reviewed
      candidate; fresh-host installation and the matching public manual pass.
      The existing latest-0.x support policy remains in effect.

- [ ] **R6 · Finish the adoption and compatibility review.** R1–R5 findings are
      completed or explicitly dispositioned, the supported API is accepted, and
      the published-package upgrade and documented operations profile pass.
- [ ] **R6 · Verify the exact candidate.** Preserve the complete local
      Ruby/Rails, SQLite/PostgreSQL, generated/ejected browser and operations
      acceptance; resolve release-blocking security and upgrade findings.
      Recheck dependency currency and pass required GitHub CI/CodeQL controls.
- [ ] **R6 · Publish and verify 1.0.** Release notes, migration/support guidance,
      protected OIDC publication, registry checksum/package verification, fresh
      installation and the public manual all identify the same accepted release.

The owner accepted local testing as the gem release gate. Production migration,
a fixed number of adopters, live captcha accounts, physical devices and branded
emails are not additional gem release requirements. Hosts remain responsible for
their actual providers, proxy/TLS, trusted recovery addresses and support process.

## Ongoing — broader compatibility evidence

- [ ] **R7 · Record browser, device and accessibility results as available.**
      Track exact Safari/Firefox/mobile/hybrid authenticator and
      assistive-technology environments. Add local regressions for reproducible
      defects and document limits.
- [ ] **R7 · Record deployment-provider results as available.** Capture actual
      provider and failure/recovery evidence without treating local protocol
      fixtures as live-service certification.

These broaden host deployment confidence; they do not reopen completed 0.2
acceptance or silently add hardware/service gates to 1.0.

## Later — evaluate demand before adding scope

These are candidates, not promised features or a committed “v2” release. A
compatible extension could ship in 1.x after an explicit scope decision.

- [ ] **F1 · Recovery codes.** First expansion candidate to assess when adopters
      need recovery beyond trusted email or strict host support. Design single
      use, regeneration/revocation, abuse controls and the recovery-policy boundary
      before implementation; codes must not silently satisfy passkey-only purposes.
- [ ] **F2 · Rails-native password hashing integration.** Recheck available Rails
      support and real adopter needs before adding an adapter or changing a default.
- [ ] **F3 · Account lifecycle helpers.** The bounded migration requirements
      are promoted to R8 above; broader module parity remains outside this scope.
- [ ] **F4 · Multiple realms.** Require a concrete identity/session-isolation need
      and migration design before adding models, cookies or routing APIs.
- [ ] **F4 · API/token authentication.** Android/iOS login is the active R8
      work above; multiple realms and general API-key management remain separate.
- [ ] **F5 · Standalone test helpers or challenge adapters.** Extract only if
      independent demand and maintenance capacity justify another package;
      retain one implementation per concern.

Optional provider-library integration is locally verified under R8. SMS/TOTP and enterprise
or cross-origin WebAuthn remain outside the current roadmap. Account roles,
invitations, authorization and email branding
stay with the host.

## Shipped — 0.2.1 baseline

- [x] Host password integration and explicit passwordless mode; one Core policy,
      result presenter and atomic session finalizer.
- [x] Random digested session bearers, bounded Rails signed-ID session adoption,
      expiry, device listing/pagination, revoke-one/all and host lifecycle invalidation.
- [x] Email links with inert GET/explicit POST confirmation, generic intake,
      resend/replay protection and optional same-browser binding.
- [x] Discoverable passkeys, conditional sign-in, UV/origin enforcement,
      credential management, counter checks and atomic last-method protection.
- [x] Purpose-bound password/email/passkey reauthentication, trusted-address
      recovery, strict opt-in policy and protected host mutations.
- [x] Durable encrypted mail/notification intents, leases, retries,
      cancellation and bounded maintenance with optional retention.
- [x] Turnstile and reCAPTCHA v2/v3 with distinct rejected/unavailable outcomes,
      bounded verification and explicit outage policy.
- [x] Additive generators, fingerprinted view/controller/JavaScript/mail ejection,
      drift diagnostics, doctor and framework-neutral testing helpers.
- [x] Shared HTML/Turbo pages, permitted no-JS alternatives, browser
      capability detection and cache/CSRF/privacy protections.
- [x] Local supported Ruby 3.3/3.4/4.0 × Rails 8.0/8.1 matrix, SQLite/PostgreSQL
      concurrency, generated/ejected browser and SMTP/queue/cache acceptance.
- [x] RSpec, Standard, dependency audit, CodeQL, protected repository controls
      and pinned-action Trusted Publishing.
- [x] [Published 0.2.1](https://rubygems.org/gems/add_auth/versions/0.2.1),
      verified registry installation and the maintained public manual.

Passkeys require JavaScript and a capable browser. Configured captcha may also
require JavaScript; strict policy is never weakened to imitate no-JS parity.
The immutable 0.1.0/0.2.0 tags did not publish packages; 0.2.1 is the first
successful package release. Historical details remain in the changelog and
release records.

For application setup, start with the [quickstart](https://addauthgem.com/quickstart/).
Report bugs or adoption feedback through [public issues](https://github.com/taimoorq/add_auth/issues);
use [private vulnerability reporting](SECURITY.md) for security concerns.
