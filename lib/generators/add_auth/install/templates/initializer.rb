# frozen_string_literal: true

# AddAuth settings. Defaults are active; alternatives are commented out.
# Run the relevant generator and migrations before enabling a feature.
# Install alone enables no features. Existing initializers are never replaced.
AddAuth.configure do |config|
  # Sign-in and rendering. HTML forms work in all browser modes.
  config.passwords_enabled = true
  # config.passwords_enabled = false # Use only other explicitly enabled methods.
  config.turbo_enabled = true
  # config.turbo_enabled = false # Ordinary JS navigation, with Turbo absent.

  # Host business eligibility is checked alongside Core account policy.
  config.eligible = ->(_user) { true }
  # config.eligible = ->(user) { user.access_state == "active" }

  # Browser sessions: bin/rails generate add_auth:session_upgrade
  config.session.enabled = false
  config.session.lifetime = 43_200 # 12 hours, absolute expiry.
  config.session.idle_timeout = 1800 # 30 minutes; no greater than lifetime.
  config.session.legacy_bridge_until = nil # Reject old Rails session-ID cookies.
  # config.session.legacy_bridge_until = Time.iso8601("2030-01-01T00:00:00Z")
  # Choose a short, fixed cutover deadline for a reviewed legacy-cookie bridge.

  # Account lifecycle: bin/rails generate add_auth:accounts
  # Password-only host: bin/rails generate add_auth:accounts --no-email-link
  config.lifecycle.enabled = false
  # config.lifecycle.enabled = true # After policy review and migrations.
  config.lifecycle.confirmation_required = true
  # config.lifecycle.confirmation_required = false
  # false: password signup provisions and signs in immediately, without mail.
  # confirmed_at stays nil. Requires the add_auth_provisioned_at migration.
  config.lifecycle.reset_unconfirmed = false
  # config.lifecycle.reset_unconfirmed = true # Requires optional confirmation.
  # true: the stored mailbox holder may reset an unconfirmed password account
  # after consuming an exact-address, single-use reset proof. No automatic login
  # or confirmation. This does not trust the address for any other recovery.
  # false: confirm the address before password reset, or use host support.
  # Email changes always need fresh reauthentication and proof of the new address.
  config.lifecycle.password_policy = ->(password) { password.length >= 12 && password.bytesize <= 72 }
  config.lifecycle.eligible = ->(_user) { true } # Additional lifecycle eligibility.
  config.lifecycle.profile_attributes = ->(_profile) { {} } # Accept no profile fields.
  # config.lifecycle.profile_attributes = ->(profile) { profile.slice(:name, :consent) }
  # Also allowlist those fields in the host registration controller. Never roles.
  config.lifecycle.provision = ->(_user) {} # Local writes in the account transaction.
  # config.lifecycle.provision = ->(user) { user.create_personal_workspace! }
  # Raise on failure. Use the same DB pool; remote work needs a host outbox.
  config.lifecycle.maximum_attempts = 20 # Failed-password threshold: 1..100.
  config.lifecycle.unlock_in = 3600 # Timed lock: 60..86400 seconds.
  config.lifecycle.proof_lifetime = 3600 # Account links: 60..86400 seconds.
  config.lifecycle.remember_lifetime = 1_209_600 # 14 days, absolute expiry.
  config.lifecycle.remember_idle_timeout = 604_800 # 7 days; <= remember_lifetime.
  config.lifecycle.deletion_allowed = ->(_user) { true } # Host authorization/retention.
  # config.lifecycle.deletion_allowed = ->(user) { user.invoices.none? }
  config.lifecycle.delete_account = ->(user) { user.destroy! } # Same-DB local deletion.

  # Email-link sign-in: bin/rails generate add_auth:email_link
  # Account confirmation/reset mail does not require email-link sign-in.
  config.email_link.enabled = false
  config.email_link.token_lifetime = 1200 # 20 minutes.
  config.email_link.same_browser = false
  # config.email_link.same_browser = true # Require the requesting browser.

  # Fresh proof for sensitive actions: bin/rails generate add_auth:step_up
  # Use --no-email-link for password-only reauthentication.
  config.step_up.enabled = false
  config.step_up.fresh_for = 600 # Ordinary proof: 10 minutes.
  config.step_up.strong_for = 300 # Strong proof: 5 minutes.
  config.step_up.purposes = {} # Built-in feature purposes are supplied by Core.
  # config.step_up.purposes = {
  #   export_data: {methods: [:password], return_to: "/exports/new", label: "export your data"}
  # }
  # Recheck elevation and host authorization inside the actual mutation.

  # Passkeys: bin/rails generate add_auth:passkeys
  config.passkeys.enabled = false
  config.passkeys.rp_id = nil # Required: stable deployment RP ID.
  # config.passkeys.rp_id = "example.com"
  config.passkeys.origins = [] # Required: exact trusted origins, never request Host.
  # config.passkeys.origins = ["https://app.example.com"]
  config.passkeys.name = "Your account"
  config.passkeys.anonymous_limit = 1000 # Shared ceremony budget per five minutes.
  config.trusted_recovery_address = ->(_user) {} # No trusted recovery by default.
  # config.trusted_recovery_address = ->(user) { user.email_address if user.confirmed_at }
  # Lifecycle additionally rejects unconfirmed addresses as trusted recovery.
  config.support_url = nil # Required before strict-policy activation.
  # config.support_url = "/support" # Document your host-owned recovery process.

  # Security notices: bin/rails generate add_auth:notifications
  config.notifications.enabled = false
  # Mail/queue settings also serve account proofs and optional email sign-in.
  config.base_url = nil # Required for links: fixed trusted HTTPS origin.
  # config.base_url = "https://app.example.com"
  config.mail_from = nil # Required for mail; configure SMTP in Rails as usual.
  # config.mail_from = "Your app <sign-in@example.com>"
  # Configure a durable Active Job adapter and run add_auth:deliver_pending each minute.
  config.rate_limit_store = nil # Defaults to Rails.cache; shared atomic counters required.
  # config.rate_limit_store = ActiveSupport::Cache::RedisCacheStore.new(url: ENV.fetch("AUTH_REDIS_URL"))
  # Solid Cache can serve application caching, but cannot serve these counters.
  config.maintenance.batch_size = 100 # Maximum rows per operation/model: 1..1000.
  config.maintenance.session_retention = nil # Keep history until explicitly selected.
  config.maintenance.email_retention = nil
  config.maintenance.notification_retention = nil
  config.maintenance.account_retention = nil
  # config.maintenance.session_retention = 604_800 # 7 days, seconds.
  # config.maintenance.email_retention = 604_800
  # config.maintenance.notification_retention = 2_592_000 # 30 days.
  # config.maintenance.account_retention = 604_800

  # Captcha: bin/rails generate add_auth:challenge (provider-specific setup).
  config.challenge = AddAuth::Core::Challenge::Null.new
  config.challenge_on = [] # Available: sign_in, email_link, reauthenticate,
  # passkey_enrollment, register, account_request, provider.
  # config.challenge_on = [:sign_in, :register, :account_request]
  config.challenge_when_unavailable = :closed
  # config.challenge_when_unavailable = :open # Explicit outage bypass; emits an event.
  # Replace challenge with a configured Turnstile or Recaptcha adapter. Keep
  # secrets in Rails credentials/environment, and configure expected hostnames.

  # Optional providers: bin/rails generate add_auth:external_identities
  config.external_identities.enabled = false
  # Register only reviewed Core provider configurations through
  # config.external_identities.register(id:, label:, middleware_name:, configuration:,
  #   apple_form_post: false, reauthentication: false)
  # or config.external_identities.register_native(configuration:).
  # The generated add_auth_providers.rb explains provider-library middleware,
  # verifier and credential setup. It remains commented out until reviewed.

  # Native sessions: bin/rails generate add_auth:mobile_sessions
  config.mobile.enabled = false
  config.mobile.lifetime = nil # Required when enabled; choose finite seconds.
  config.mobile.idle_timeout = nil # Required; <= lifetime.
  config.mobile.clients = [] # Explicit first-party client identifiers.
  config.mobile.callbacks = {} # Reviewed callbacks per client, when using handoffs.
  config.mobile.apple_providers = {} # Native Apple provider IDs per client.
  # config.mobile.lifetime = 2_592_000 # Example: 30 days.
  # config.mobile.idle_timeout = 1_209_600 # Example: 14 days.
  # config.mobile.clients = %w[android ios]

  # Presentation: eject with bin/rails generate add_auth:views.
  config.stylesheet = "/add_auth.css"
  # config.stylesheet = nil # Supply your own styling.
  config.css_classes = {}
  # config.css_classes = {input: "form-control", button: "btn btn-primary"}

  # Password migration and cryptography: retain Rails' verifier by default.
  config.legacy_password_verifier = nil
  config.current_password_support = AddAuth::Core::Passwords::BcryptSupport.new
  # A custom verifier must also declare current_password_support.available?(digest:).
  # Rails configures digest_secret from its key generator automatically. Preserve it.
  # Outside Rails only:
  # config.digest_secret = -> { ENV.fetch("ADD_AUTH_DIGEST_SECRET") }
  # Optional adapter overrides must implement digest(token) and matches?(digest, token):
  # config.session_token_digest = MySessionDigest.new
  # config.sign_in_token_digest = MyProofDigest.new
end
