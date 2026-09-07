# frozen_string_literal: true

require "rails/generators"
require "generators/latchkey/ejection"

module Latchkey
  module Generators
    class JavascriptGenerator < ::Rails::Generators::Base
      include Ejection

      def generate = eject(:javascript)
    end
  end
end
