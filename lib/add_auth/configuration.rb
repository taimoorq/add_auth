# frozen_string_literal: true

module AddAuth
  class Configuration
    attr_accessor :challenge, :challenge_on,
      :digest_secret, :eligible, :stylesheet, :css_classes, :mail_from, :base_url, :rate_limit_store, :trusted_recovery_address, :support_url
    attr_writer :session_token_digest, :sign_in_token_digest

    SessionOptions = Struct.new(:enabled, :lifetime, :idle_timeout, :legacy_bridge_until)
    EmailOptions = Struct.new(:enabled, :token_lifetime, :same_browser)
    StepUpOptions = Struct.new(:enabled, :purposes, :fresh_for, :strong_for)
    PasskeyOptions = Struct.new(:enabled, :rp_id, :origins, :name, :anonymous_limit)
    NotificationOptions = Struct.new(:enabled)
    MaintenanceOptions = Struct.new(:batch_size, :session_retention, :email_retention, :notification_retention)
    attr_accessor :passwords_enabled
    attr_reader :maintenance, :notifications, :passkeys, :session, :email_link, :step_up, :challenge_when_unavailable

    def initialize
      @passwords_enabled = true
      @session = SessionOptions.new(enabled: false, lifetime: 43_200, idle_timeout: 1800)
      @email_link = EmailOptions.new(enabled: false, token_lifetime: 1200, same_browser: false)
      @notifications = NotificationOptions.new(enabled: false)
      @maintenance = MaintenanceOptions.new(batch_size: 100)
      @passkeys = PasskeyOptions.new(enabled: false, origins: [], name: "Your account", anonymous_limit: 1000)
      @trusted_recovery_address = ->(_user) {}
      @step_up = StepUpOptions.new(enabled: false, purposes: {}, fresh_for: 600, strong_for: 300)
      @eligible = ->(_user) { true } # Hosts supply their confirmed/locked/disabled policy here.
      @stylesheet = "/add_auth.css"
      @css_classes = {}
      @challenge = Core::Challenge::Null.new
      @challenge_on = []
      @challenge_when_unavailable = :closed
    end

    def session_token_digest
      @session_token_digest ||= default_digest("add_auth.session-token-digest.v1")
    end

    def sign_in_token_digest
      @sign_in_token_digest ||= default_digest("add_auth.sign-in-token-digest.v1")
    end

    def challenge_when_unavailable=(policy)
      value = policy.to_sym
      raise ArgumentError, "challenge_when_unavailable must be :closed or :open" unless %i[closed open].include?(value)

      @challenge_when_unavailable = value
    rescue NoMethodError
      raise ArgumentError, "challenge_when_unavailable must be :closed or :open"
    end

    private

    def default_digest(salt)
      unless digest_secret.respond_to?(:call)
        raise AddAuth::Error, "configure digest_secret or inject a digest adapter outside a Rails app"
      end
      Core::Digest::Hmac.new(salt: salt, secret: digest_secret.call)
    end
  end
end
