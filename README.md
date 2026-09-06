# Latchkey

**Status: pre-implementation skeleton. Nothing in this repository works yet.**
Every strategy, generator, and engine hook below raises `NotImplementedError`
on purpose -- this commit establishes the file layout the design calls for,
not a release.

Latchkey extends the output of `bin/rails generate authentication` (Rails 8's
built-in generator) with the credentials it doesn't cover:

- **Email-link sign-in** -- passwordless, POST-to-consume by default (GET-to-consume
  links get silently burned by corporate mail scanners and link-unfurlers
  before a human ever clicks them).
- **Passkeys** -- registration, discoverable sign-in, and conditional UI
  (autofill) via [webauthn-ruby](https://github.com/cedarcode/webauthn-ruby).
- **Step-up (elevated) sessions** -- a session established by a 20-day-old
  email link isn't the right authority to enroll a new passkey or change an
  email address; `require_elevated_session` fixes that without a second
  cookie.
- **Pluggable challenges** -- Turnstile/reCAPTCHA adapters with a real
  `unavailable?` state, distinct from `rejected?`, so a provider outage and a
  failed human challenge don't get treated the same way.

It deliberately does **not** replace the generator, its `Session` model, or
Devise. See the design doc for the full reasoning, the architecture, the
schema, and -- importantly -- the landscape review that scoped this down from
a Devise-replacement to a strategy layer:

**[docs/authentication-gem-plan.md](https://github.com/taimoorq/latchkey-workspace/blob/main/docs/authentication-gem-plan.md)**
(in the companion private workspace repo -- not in this repo, since it also
covers scope this repo doesn't implement yet).

## Layout

```
lib/latchkey/
  version.rb, result.rb, configuration.rb   # entry point, closed Result type
  core/                                      # Layer 1 -- plain Ruby, no Rails.
    strategies/email_link.rb, passkey.rb     #   Every security decision lives
    challenge/base.rb, null.rb, test.rb      #   here. See design doc section 2.
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
section 11 for the fingerprinted-ejection plan.

## Scope

v1 is scoped to the four items above, plus session hardening applied to the
generator's own `Session` model (in place -- no parallel session concept) and
Hotwire/no-JS-compatible generated views. Devise-parity password workflows
(registration, password reset, confirmable, lockable, validatable) are
specified in the design doc but deferred to v2, pending real usage data. See
design doc sections 14 and 15.

## Roadmap

Track v1 progress in [ROADMAP.md](ROADMAP.md) -- checked off incrementally as
each piece lands, derived from the design doc's scope decision.

## Contributing

Not yet accepting contributions -- v1 doesn't exist yet. Filing issues that
poke holes in the design doc or the roadmap is welcome.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
