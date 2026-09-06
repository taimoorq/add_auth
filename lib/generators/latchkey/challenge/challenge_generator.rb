# frozen_string_literal: true

require "rails/generators"

module Latchkey
  module Generators
    # `bin/rails g latchkey:challenge` -- see docs/authentication-gem-plan.md
    # section 11 for what this generator is responsible for.
    class ChallengeGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      def generate
        say "latchkey:challenge is not implemented yet -- see docs/authentication-gem-plan.md section 11", :yellow
      end
    end
  end
end
