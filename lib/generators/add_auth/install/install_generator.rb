# frozen_string_literal: true

require "rails/generators"

module AddAuth
  module Generators
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      def verify_host
        %w[app/models/user.rb app/models/session.rb app/controllers/concerns/authentication.rb].each do |path|
          raise Thor::Error, "Run the Rails authentication generator first (missing #{path})." unless File.file?(File.join(destination_root, path))
        end
      end

      def configuration
        copy_file "initializer.rb", "config/initializers/add_auth.rb" unless File.exist?(File.join(destination_root, "config/initializers/add_auth.rb"))
      end

      def report
        say "AddAuth: host authentication files found. Install enables no features."
        rails_command "add_auth:doctor", abort_on_failure: false
        say "Run add_auth:session_upgrade or add_auth:email_link, review migrations, then run bin/rails add_auth:doctor."
      end
    end
  end
end
