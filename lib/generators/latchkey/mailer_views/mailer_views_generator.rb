# frozen_string_literal: true

require "rails/generators"
require "generators/latchkey/ejection"

module Latchkey
  module Generators
    class MailerViewsGenerator < ::Rails::Generators::Base
      include Ejection

      def generate = eject(:mailer_views)
    end
  end
end
