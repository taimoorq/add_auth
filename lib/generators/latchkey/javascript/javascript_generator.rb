# frozen_string_literal: true

require "rails/generators"

module Latchkey
  module Generators
    # `bin/rails g latchkey:javascript` -- see docs/authentication-gem-plan.md
    # section 11 for what this generator is responsible for.
    class JavascriptGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      def generate
        say "latchkey:javascript is not implemented yet -- see docs/authentication-gem-plan.md section 11", :yellow
      end
    end
  end
end
