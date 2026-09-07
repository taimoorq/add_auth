require "latchkey/rails/authentication"
require "latchkey/rails/user_lifecycle"
# Latchkey configuration. Feature generators enable only their own block.
Latchkey.configure do |config|
  # BEGIN latchkey session
  config.session.enabled = true
  # END latchkey session
  # config.session.lifetime = 12.hours
  # config.session.idle_timeout = 30.minutes
  # Legacy cookies are rejected by default. Opt into a finite bridge explicitly:
  # config.session.legacy_bridge_until = Time.iso8601("2026-09-13T00:00:00Z")

  # BEGIN latchkey email_link
  config.email_link.enabled = true
  # END latchkey email_link
  # config.email_link.token_lifetime = 20.minutes
  # REQUIRED for email delivery: fixed, trusted origin; never derive it from Host.
  # config.base_url = "https://your-app.example"
  # config.mail_from = "Your app <sign-in@your-app.example>"
  # Configure a durable Active Job adapter and schedule latchkey:deliver_pending.
  # config.rate_limit_store = Rails.cache # shared, atomic increment in production

  # Apply the host's current confirmed/locked/disabled policy on every resume:
  # config.eligible = ->(user) { user.confirmed? && !user.locked? && !user.disabled? }

  # Styling: nil disables CSS; a local path uses your own compiled stylesheet.
  # config.stylesheet = "/latchkey.css"
  # config.css_classes = { input: "form-control", button: "btn btn-primary" }
  # Eject editable templates with bin/rails generate latchkey:views.

  # Passkeys and public step-up/recovery remain upcoming. Challenge adapters
  # are available through latchkey:challenge; its widget route is opt-in.
  # These feature generators are not enabled by install. See ROADMAP.md for scope.
  # Email recovery is the planned default; stricter policy will be opt-in.
  # config.challenge = Latchkey::Core::Challenge::Null.new
  # config.challenge_on = []
end

Latchkey.configure do |config|
  config.base_url = "http://example.test"
  config.mail_from = "Sign in <sign-in@example.test>"
  config.rate_limit_store = ActiveSupport::Cache::MemoryStore.new
end
