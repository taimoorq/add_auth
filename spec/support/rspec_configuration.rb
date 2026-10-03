# frozen_string_literal: true

require "rspec/core"
require_relative "test_reporting"

RSpec.configure do |config|
  config.fail_if_no_examples = true
  if ENV["CI"]
    config.define_derived_metadata(focus: true) { raise "Focused RSpec metadata is forbidden in CI" }
    # Inner acceptance groups can be defined before their browser helper loads.
    config.before(:suite) do
      groups = RSpec.world.all_example_groups
      if groups.any? { |group| group.metadata[:focus] || group.examples.any? { |example| example.metadata[:focus] } }
        raise "Focused RSpec metadata is forbidden in CI"
      end
    end
  end
  if AddAuthTestReporting.directory
    require_relative "json_formatter"
    # Adding JSON must not suppress RSpec's otherwise implicit console formatter.
    config.add_formatter(:progress) if config.formatters.empty?
    config.add_formatter(AddAuthJSONFormatter.new(AddAuthTestReporting.rspec_path))
    config.profile_examples = 10
  end
end
