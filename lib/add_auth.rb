# frozen_string_literal: true

require "add_auth/version"
require "add_auth/result"
require "add_auth/configuration"

# Layer 1 (plain Ruby, no Rails dependency). See
# docs/authentication-gem-plan.md section 2 in the workspace repo for the
# two-layer architecture this module is built around: AddAuth::Core holds
# every security decision and knows nothing about controllers, views, or the
# session hash. AddAuth::Rails (loaded below, only inside a Rails app) is the
# thin engine that wires Core into a host application and generates
# ejectable, disposable UI on top of it.
require "add_auth/core/browser_binding"
require "add_auth/core/access_policy"
require "add_auth/core/account_policy"
require "add_auth/core/sessions"
require "add_auth/core/mobile_response"
require "add_auth/core/step_up"
require "add_auth/core/external_identities"
require "add_auth/core/intake"
require "add_auth/core/rate_limit"
require "add_auth/core/delivery"
require "add_auth/core/account_lifecycle"
require "add_auth/core/maintenance"
require "add_auth/core/security_events"
require "add_auth/core/strategies/email_link"
require "add_auth/core/strategies/passkey"
require "add_auth/core/challenge/base"
require "add_auth/core/challenge/http"
require "add_auth/core/challenge/null"
require "add_auth/core/challenge/test"
require "add_auth/core/challenge/turnstile"
require "add_auth/core/challenge/recaptcha"
require "add_auth/core/digest/base"
require "add_auth/core/digest/hmac"

module AddAuth
  class Error < StandardError; end

  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield configuration
    end
  end
end

if defined?(::Rails::Engine)
  require "add_auth/rails/engine"
  require "add_auth/rails/delivery_cipher"
  require "add_auth/rails/stores/email_tokens"
end
