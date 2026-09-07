# frozen_string_literal: true

require "rails/generators"
require "generators/add_auth/ejection"

module AddAuth
  module Generators
    class ControllersGenerator < ::Rails::Generators::Base
      include Ejection

      def generate = eject(:controllers)
    end
  end
end
