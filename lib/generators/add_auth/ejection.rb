# frozen_string_literal: true

require "add_auth/rails/ejection"

module AddAuth
  module Generators
    module Ejection
      private

      def eject(kind, only: "all")
        Rails::Ejection.new(host_root: destination_root).install(kind: kind, only: only).each do |result|
          say "#{result[:preserved] ? "Preserved" : "Created"} #{result[:path]}"
        end
        say "Run bin/rails add_auth:doctor after gem upgrades to review upstream changes."
      end
    end
  end
end
