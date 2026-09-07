# Security policy

Latchkey handles authentication credentials -- passwords (via the host app),
passkeys, session and sign-in tokens, and cryptographic digests. Please report
suspected vulnerabilities privately rather than opening a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
https://github.com/taimoorq/latchkey/security/advisories/new

If that isn't available to you, email taimoorq@gmail.com with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept if you have one.
- The Latchkey version, Rails version, and Ruby version involved.

Please do not disclose the issue publicly (including in a GitHub issue,
mailing list, or social media) until a fix has been released.

## What's in scope

- The `Latchkey::Core` cryptographic and authentication logic (token issuance
  and consumption, session adoption/resume/revocation, session/sign-in
  digesting, rate limiting and account eligibility).
- The encrypted email intake/outbox, worker retry/lease semantics and default
  mail logging, plus the durable security-notification outbox.
- WebAuthn registration/assertion, UV, origin/RP and ownership verification,
  single-use ceremonies, counters, last-credential concurrency and management.
- Purpose-bound password/email/passkey reauthentication, bearer rotation,
  trusted-address recovery, strict policy and host mutation-guard contracts.
- The Turnstile and reCAPTCHA challenge adapters, their server-side verification
  contract and scoped browser lifecycle, including failure, outage and Turbo
  replacement handling.
- The generated controllers and views this gem ships,
  including their CSRF, enumeration-safety, and Turbo-Stream behavior.
- The GitHub Actions release pipeline (`.github/workflows/push_gem.yml`) and
  its Trusted Publishing configuration.

Vulnerabilities in Rails itself, in `webauthn-ruby`, or in `bcrypt`/`argon2`
should be reported to those projects directly; Latchkey will pick up fixed
releases via Dependabot (see `AGENTS.md` in the companion workspace repo for
the currency policy).

## Supported versions

Until a 1.0 is released, only the latest published version receives security
fixes. This table will be expanded once there are stable release lines to
support.

| Version | Supported |
| ------- | --------- |
| latest 0.x | :white_check_mark: |
| older 0.x  | :x: |

## Response expectations

This is currently a single-maintainer project. Please allow a reasonable
window for an initial response before following up, and understand that a fix
timeline depends on severity and complexity.

## Recovery and deployment boundaries

The 0.2 development line includes default email replacement only when
an explicit host callback returns a verified recovery address. Strict accounts
cannot use password or email recovery; they require a remaining passkey or the
host's documented support process. Password reset and feature disablement must
not relax strict policy. Report any contrary behavior as a policy bypass.

See README's operations and rollback instructions for log filtering, encrypted
outbox handling, key rotation and migration safety. Hosts own account eligibility,
address confirmation, resource authorization, SMTP/queue/cache/proxy configuration
and support recovery. A local test suite does not certify those deployments.
