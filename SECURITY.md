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
  and consumption, passkey registration/authentication, session/sign-in
  digesting, rate limiting).
- The generated controllers, views, and Stimulus controllers this gem ships,
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
