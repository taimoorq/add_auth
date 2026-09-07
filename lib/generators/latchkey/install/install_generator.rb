# frozen_string_literal: true

require "rails/generators"

module Latchkey
  module Generators
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      def verify_host
        %w[app/models/user.rb app/models/session.rb app/controllers/concerns/authentication.rb].each do |path|
          raise Thor::Error, "Run the Rails authentication generator first (missing #{path})." unless File.file?(File.join(destination_root, path))
        end
      end

      def configuration
        copy_file "initializer.rb", "config/initializers/latchkey.rb" unless File.exist?(File.join(destination_root, "config/initializers/latchkey.rb"))
      end

      def report
        say "Latchkey: host authentication files found. Install enables no features."
        rails_command "latchkey:doctor", abort_on_failure: false
        say "Run latchkey:session_upgrade or latchkey:email_link, review migrations, then run bin/rails latchkey:doctor."
      end
    end
  end
end
