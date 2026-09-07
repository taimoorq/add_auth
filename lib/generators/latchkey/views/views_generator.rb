# frozen_string_literal: true

require "rails/generators"
require "generators/latchkey/ejection"

module Latchkey
  module Generators
    class ViewsGenerator < ::Rails::Generators::Base
      include Ejection

      class_option :only, type: :string, default: "email_link"

      def generate = eject(:views, only: options[:only])
    end
  end
end
