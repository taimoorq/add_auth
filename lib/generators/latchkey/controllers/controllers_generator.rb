# frozen_string_literal: true

require "rails/generators"
require "generators/latchkey/ejection"

module Latchkey
  module Generators
    class ControllersGenerator < ::Rails::Generators::Base
      include Ejection

      def generate = eject(:controllers)
    end
  end
end
