# frozen_string_literal: true

require "rspec/core/formatters/json_formatter"
require "stringio"

class AddAuthJSONFormatter < RSpec::Core::Formatters::JsonFormatter
  RSpec::Core::Formatters.register self, :message, :dump_summary, :dump_profile, :stop, :seed, :close

  def initialize(path)
    @path = path
    # Capybara-only Rails runners load this helper but never execute RSpec.
    # Materialize a report only when a real run closes, including empty runs.
    super(StringIO.new)
  end

  def close(notification)
    super
    File.write(@path, output.string)
  end

  def stop(notification)
    super
    output_hash[:examples].zip(notification.notifications).each do |row, item|
      row[:browser] = item.example.metadata[:browser] == true
      row[:browser_mode] = item.example.metadata[:browser_mode]&.to_s
      row[:protocol_negative] = item.example.metadata[:protocol_negative] == true
      row[:owner_file] = item.example.example_group.parent_groups.last.metadata[:file_path]
    end
    output_hash[:execution] = {main: ENV["ADD_AUTH_RSPEC_MAIN"] == "1", invocation: ENV["ADD_AUTH_RSPEC_INVOCATION"],
                              ruby: RUBY_VERSION, rails: Gem.loaded_specs["railties"]&.version&.to_s,
                              ejected: ENV["ADD_AUTH_EJECT_UI"] == "1", turbo: ENV["ADD_AUTH_TURBO"] != "0"}
  end
end
