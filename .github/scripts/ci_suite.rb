# frozen_string_literal: true

require "fileutils"
require "rbconfig"
require "rubygems/package"
require_relative "ci_matrix"

module AddAuthCISuite
  module_function

  def run!
    kind, rails, suite = ARGV
    ruby = RUBY_VERSION.split(".").first(2).join(".")
    raise "Unsupported Ruby/Rails shard" unless AddAuthCIMatrix::RUBIES.include?(ruby) && AddAuthCIMatrix::RAILS.include?(rails)
    planned = AddAuthCIMatrix.plan(kind, suite)
    profile = AddAuthCIMatrix.profile(kind, suite)
    expected_bundle = File.expand_path("gemfiles/#{profile}_#{rails}.gemfile")
    raise "CI shard needs its own #{profile}/#{rails} bundle" unless File.expand_path(ENV.fetch("BUNDLE_GEMFILE")) == expected_bundle
    directory = File.expand_path(ENV.fetch("ADD_AUTH_CI_REPORT_ROOT", "tmp/ci-reports/#{kind}-#{ruby}-#{rails}-#{suite}"))
    raise "Refusing to reuse CI report output" if File.exist?(directory)
    FileUtils.mkdir_p(directory)
    sha, status = Open3.capture2("git", "rev-parse", "HEAD")
    raise "Cannot identify candidate" unless status.success?
    receipt = {"kind" => kind, "ruby" => ruby, "rails" => rails, "suite" => suite, "sha" => sha.strip,
               "source" => AddAuthCIMatrix.source_identity, "run_id" => ENV.fetch("GITHUB_RUN_ID", "local"),
               "attempt" => ENV.fetch("GITHUB_RUN_ATTEMPT", "1"), "status" => "running", "invocations" => []}
    File.write(File.join(directory, "receipt.json"), JSON.pretty_generate(receipt))
    begin
      if kind == "ruby" && suite == "product"
        AddAuthCIMatrix::BASELINES.each do |version|
          path = File.expand_path("add_auth-#{version}.gem")
          unless File.file?(path)
            raise "Cannot fetch published upgrade baseline" unless system(RbConfig.ruby, "-S", "gem", "fetch", "add_auth", "--version", version)
          end
          specification = Gem::Package.new(path).spec
          raise "Wrong upgrade baseline package" unless specification.name == "add_auth" && specification.version.to_s == version
        end
      end
      planned.each do |invocation|
        execute!(invocation, receipt, directory)
        File.write(File.join(directory, "receipt.json"), JSON.pretty_generate(receipt))
      end
      receipt["status"] = "passed"
      AddAuthCIMatrix.verify_shard!(receipt, directory: directory, ruby: ruby, rails: rails, suite: suite, kind: kind,
        sha: sha.strip, source: receipt.fetch("source"), run_id: receipt.fetch("run_id"), attempt: receipt.fetch("attempt"))
    rescue
      receipt["status"] = "failed"
      raise
    ensure
      File.write(File.join(directory, "receipt.json"), JSON.pretty_generate(receipt))
    end
  end

  def execute!(invocation, receipt, directory)
    label = invocation.fetch("label")
    report_directory = File.join(directory, label)
    environment = {"ADD_AUTH_EJECT_UI" => nil, "ADD_AUTH_TURBO" => nil, "ADD_AUTH_RSPEC_MAIN" => "1",
                   "ADD_AUTH_RSPEC_INVOCATION" => label, "ADD_AUTH_REPORT_DIR" => report_directory,
                   "ADD_AUTH_FIXTURE_CACHE" => File.join(File.dirname(directory), "fixture-cache")}.merge(invocation.fetch("env"))
    if (version = environment.delete("ADD_AUTH_BASELINE_VERSION"))
      environment["ADD_AUTH_BASELINE_GEM"] = File.expand_path("add_auth-#{version}.gem")
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "Running #{label}: #{invocation.fetch("args").join(" ")}"
    FileUtils.mkdir_p(report_directory)
    File.open(File.join(report_directory, "rspec.log"), "w") do |log|
      Open3.popen2e(environment, RbConfig.ruby, Gem.bin_path("bundler", "bundle"), "exec", "rspec",
        "--options", File::NULL, "--require", "spec_helper", "--format", "progress", *invocation.fetch("args")) do |input, output, wait|
        input.close
        output.each_line { |line|
          log.write(line)
          $stdout.write(line)
        }
        raise "RSpec #{label} failed (see its report artifact)" unless wait.value.success?
      end
    end
    rows = Dir[File.join(report_directory, "rspec-*.json")].sort.map do |path|
      {"path" => path.delete_prefix(directory + File::SEPARATOR), "sha256" => Digest::SHA256.file(path).hexdigest}
    end
    receipt.fetch("invocations") << invocation.merge("reports" => rows,
      "seconds" => Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
  end
end

AddAuthCISuite.run! if $PROGRAM_NAME == __FILE__
