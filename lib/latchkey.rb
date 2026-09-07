# frozen_string_literal: true

require "latchkey/version"
require "latchkey/result"
require "latchkey/configuration"

# Layer 1 (plain Ruby, no Rails dependency). See
# docs/authentication-gem-plan.md section 2 in the workspace repo for the
# two-layer architecture this module is built around: Latchkey::Core holds
# every security decision and knows nothing about controllers, views, or the
# session hash. Latchkey::Rails (loaded below, only inside a Rails app) is the
# thin engine that wires Core into a host application and generates
# ejectable, disposable UI on top of it.
require "latchkey/core/browser_binding"
require "latchkey/core/access_policy"
require "latchkey/core/sessions"
require "latchkey/core/step_up"
require "latchkey/core/intake"
require "latchkey/core/rate_limit"
require "latchkey/core/delivery"
require "latchkey/core/security_events"
require "latchkey/core/strategies/email_link"
require "latchkey/core/strategies/passkey"
require "latchkey/core/challenge/base"
require "latchkey/core/challenge/http"
require "latchkey/core/challenge/null"
require "latchkey/core/challenge/test"
require "latchkey/core/challenge/turnstile"
require "latchkey/core/challenge/recaptcha"
require "latchkey/core/digest/base"
require "latchkey/core/digest/hmac"

module Latchkey
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
  require "latchkey/rails/engine"
  require "latchkey/rails/delivery_cipher"
  require "latchkey/rails/stores/email_tokens"
end
