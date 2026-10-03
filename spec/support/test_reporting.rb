# frozen_string_literal: true

require "json"
require "fileutils"
require "securerandom"

# Private test-harness evidence, including Rails runner processes in installed hosts.
module AddAuthTestReporting
  module_function

  def directory
    ENV["ADD_AUTH_REPORT_DIR"]
  end

  def rspec_path
    FileUtils.mkdir_p(directory)
    File.join(directory, "rspec-#{Process.pid}-#{SecureRandom.hex(4)}.json")
  end

  def measure(phase)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    success = false
    value = yield
    success = true
    value
  ensure
    if directory
      FileUtils.mkdir_p(directory)
      row = {phase: phase, seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
             success: success, pid: Process.pid}
      File.open(File.join(directory, "host-phases.jsonl"), "a") do |file|
        file.flock(File::LOCK_EX)
        file.puts(JSON.generate(row))
      end
    end
  end

  def verify_examples!(output, expected:)
    counts = output.scan(/^(\d+) examples?, (\d+) failures?/).map { |count, failures| [count.to_i, failures.to_i] }
    unless expected.positive? && counts.last == [expected, 0]
      raise "Installed-host RSpec needs #{expected} examples and zero failures; got #{counts.last.inspect}"
    end
    output
  end
end
