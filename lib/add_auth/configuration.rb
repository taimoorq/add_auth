# frozen_string_literal: true

require "add_auth/core/passwords/bcrypt_support"

module AddAuth
  class Configuration
    attr_accessor :challenge, :challenge_on,
      :digest_secret, :eligible, :stylesheet, :css_classes, :mail_from, :base_url, :rate_limit_store, :trusted_recovery_address, :support_url, :legacy_password_verifier, :current_password_support
    attr_writer :session_token_digest, :sign_in_token_digest

    SessionOptions = Struct.new(:enabled, :lifetime, :idle_timeout, :legacy_bridge_until)
    MobileOptions = Struct.new(:enabled, :lifetime, :idle_timeout, :clients, :callbacks, :apple_providers)
    EmailOptions = Struct.new(:enabled, :token_lifetime, :same_browser)
    StepUpOptions = Struct.new(:enabled, :purposes, :fresh_for, :strong_for)
    PasskeyOptions = Struct.new(:enabled, :rp_id, :origins, :name, :anonymous_limit)
    NotificationOptions = Struct.new(:enabled)
    MaintenanceOptions = Struct.new(:batch_size, :session_retention, :email_retention, :notification_retention, :account_retention)
    LifecycleOptions = Struct.new(:enabled, :password_policy, :eligible, :provision, :profile_attributes, :maximum_attempts, :unlock_in, :proof_lifetime, :remember_lifetime, :remember_idle_timeout, :deletion_allowed, :delete_account)
    class ExternalProvider
      attr_reader :id, :label, :middleware_name, :configuration, :apple_form_post, :reauthentication

      def initialize(id:, label:, middleware_name:, configuration:, apple_form_post: false, reauthentication: false)
        @id, @label, @middleware_name = [id, label, middleware_name].map { |value| text(value) }
        raise ArgumentError, "external provider middleware name is invalid" unless middleware_name.match?(/\A[a-z][a-z0-9_]{0,63}\z/)
        raise ArgumentError, "external provider configuration does not match its id" unless configuration.respond_to?(:id) && configuration.id == id
        raise ArgumentError, "Apple form_post must be explicit" unless apple_form_post == true || apple_form_post == false

        raise ArgumentError, "provider reauthentication must be explicit" unless [true, false].include?(reauthentication)
        @reauthentication = reauthentication
        @configuration, @apple_form_post = configuration, apple_form_post
        freeze
      end

      def reauthentication? = reauthentication
      def apple_form_post? = apple_form_post

      private

      def text(value)
        raise ArgumentError, "external provider value is invalid" unless value.is_a?(String) && value.valid_encoding? &&
          value.bytesize.between?(1, 2048) && !value.match?(/[\x00-\x1f\x7f]/)

        value.dup.freeze
      end
    end

    class ExternalIdentityOptions
      attr_accessor :enabled

      def initialize
        @enabled = false
        @providers = []
        @native_providers = {}
      end

      def register(**attributes)
        provider = ExternalProvider.new(**attributes)
        raise ArgumentError, "external provider id is already registered" if configurations.any? { |item| item.id == provider.id }
        raise ArgumentError, "external provider middleware is already registered" if @providers.any? { |item| item.middleware_name == provider.middleware_name }

        @providers << provider
        provider
      end

      def provider(id)
        @providers.find { |item| item.id == id.to_s }
      end

      def providers = @providers.dup.freeze

      def register_native(configuration:)
        raise ArgumentError, "a native provider configuration is required" unless configuration.is_a?(Core::ExternalIdentities::Configuration)
        raise ArgumentError, "external provider id is already registered" if configurations.any? { |item| item.id == configuration.id }
        @native_providers[configuration.id] = configuration
      end

      def native_provider(id) = @native_providers[id]
      def configurations = (providers.map(&:configuration) + @native_providers.values).freeze
    end

    attr_accessor :passwords_enabled, :turbo_enabled
    attr_reader :maintenance, :notifications, :passkeys, :session, :email_link, :step_up, :challenge_when_unavailable, :lifecycle, :external_identities, :mobile

    def initialize
      @passwords_enabled = true
      @current_password_support = Core::Passwords::BcryptSupport.new
      @turbo_enabled = true
      @lifecycle = LifecycleOptions.new(enabled: false, password_policy: ->(password) { password.length >= 12 && password.bytesize <= 72 },
        eligible: ->(_user) { true }, provision: ->(_user) {}, profile_attributes: ->(_profile) { {} }, maximum_attempts: 20, unlock_in: 3600, proof_lifetime: 3600,
        remember_lifetime: 14 * 86_400, remember_idle_timeout: 7 * 86_400,
        deletion_allowed: ->(_user) { true }, delete_account: ->(user) { user.destroy! })
      @session = SessionOptions.new(enabled: false, lifetime: 43_200, idle_timeout: 1800)
      @mobile = MobileOptions.new(enabled: false, clients: [], callbacks: {}, apple_providers: {})
      @email_link = EmailOptions.new(enabled: false, token_lifetime: 1200, same_browser: false)
      @external_identities = ExternalIdentityOptions.new
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
