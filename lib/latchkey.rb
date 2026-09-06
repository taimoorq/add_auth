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
require "latchkey/core/strategies/email_link"
require "latchkey/core/strategies/passkey"
require "latchkey/core/challenge/base"
require "latchkey/core/challenge/null"
require "latchkey/core/challenge/test"

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

require "latchkey/rails/engine" if defined?(::Rails::Engine)
