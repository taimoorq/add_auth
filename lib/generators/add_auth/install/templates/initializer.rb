# AddAuth configuration. Feature generators enable only their own block.
AddAuth.configure do |config|
  # Set false for email/passkey-only sign-in. Existing Rails password entry
  # routes remain guarded; the host owns password reset and account provisioning.
  # config.passwords_enabled = true

  # Ordinary Rails HTML navigation, including hosts without Hotwire:
  # config.turbo_enabled = false
  # Passkeys/captcha still use scoped gem JavaScript; no host JS build is needed.

  # BEGIN add_auth session
  # config.session.enabled = true
  # END add_auth session
  # config.session.lifetime = 12.hours
  # config.session.idle_timeout = 30.minutes
  # Legacy cookies are rejected by default. Opt into a finite bridge explicitly:
  # config.session.legacy_bridge_until = Time.iso8601("2026-09-13T00:00:00Z")

  # BEGIN add_auth email_link
  # config.email_link.enabled = true
  # END add_auth email_link
  # config.email_link.token_lifetime = 20.minutes
  # config.email_link.same_browser = false # true requires the requesting browser
  # REQUIRED for email delivery: fixed, trusted origin; never derive it from Host.
  # config.base_url = "https://your-app.example"
  # config.mail_from = "Your app <sign-in@your-app.example>"
  # Configure a durable Active Job adapter and schedule add_auth:deliver_pending.
  # Rails.cache is suitable only with shared atomic increments and expiry.
  # Solid Cache is not suitable; configure a separate counter store:
  # https://addauthgem.com/production/#rate-limits
  # Each maintenance pass handles at most this many rows per operation/model:
  # config.maintenance.batch_size = 100 # 1..1000
  # History is retained until the host chooses a retention period (seconds):
  # config.maintenance.session_retention = 7.days
  # config.maintenance.email_retention = 7.days
  # config.maintenance.notification_retention = 30.days

  # Apply the host's current confirmed/locked/disabled policy on every resume:
  # config.eligible = ->(user) { user.confirmed? && !user.locked? && !user.disabled? }

  # Styling: nil disables CSS; a local path uses your own compiled stylesheet.
  # config.stylesheet = "/add_auth.css"
  # config.css_classes = { input: "form-control", button: "btn btn-primary" }
  # Eject editable templates with bin/rails generate add_auth:views.

  # Enable optional features with add_auth:passkeys, add_auth:step_up,
  # add_auth:notifications or add_auth:challenge. Install alone enables none.
  # Passkey recovery needs a host-verified recovery address; strict accounts
  # use another passkey or the host's support process, never email recovery.
  # config.challenge = AddAuth::Core::Challenge::Null.new
  # config.challenge_on = []
end
