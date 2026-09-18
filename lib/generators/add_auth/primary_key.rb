# frozen_string_literal: true

module AddAuth
  module Generators
    module PrimaryKey
      private

      # Freeze Rails' generator preference into the migration source. Foreign
      # keys independently follow the actual referenced table when it runs.
      def authentication_primary_key_type
        type = (::Rails.application.config.generators.options.dig(:active_record, :primary_key_type) || :bigint).to_s
        unless %w[bigint integer uuid].include?(type)
          raise Thor::Error, "AddAuth supports Rails primary_key_type :bigint, :integer or :uuid"
        end
        ":#{type}"
      end
    end
  end
end
