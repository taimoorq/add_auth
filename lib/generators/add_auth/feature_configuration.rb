# frozen_string_literal: true

module AddAuth
  module Generators
    module FeatureConfiguration
      private

      def enable_feature(name)
        path = "config/initializers/add_auth.rb"
        source = File.read(File.join(destination_root, path))
        setting = "config.#{name}.enabled"
        pattern = /^(\s*)(?:# #{Regexp.escape(setting)} = true|#{Regexp.escape(setting)} = false)$/
        if source.match?(pattern)
          gsub_file path, pattern, "\\1#{setting} = true"
        elsif !source.match?(/^\s*#{Regexp.escape(setting)}\s*=/)
          append_to_file path, "\nAddAuth.configure do |config|\n  #{setting} = true\nend\n"
        end
      end
    end
  end
end
