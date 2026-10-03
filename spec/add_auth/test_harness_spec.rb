# frozen_string_literal: true

require "spec_helper"
require "open3"
require "tmpdir"
require "timeout"
require_relative "../support/fixture_cache"

RSpec.describe "RSpec execution guards" do
  def isolated_rspec(source, ci: "true", **options)
    Dir.mktmpdir("add-auth-rspec-guard-") do |path|
      file = File.join(path, "example_spec.rb")
      File.write(file, source)
      configuration = File.expand_path("../support/rspec_configuration.rb", __dir__)
      Open3.capture2e({"CI" => ci, "ADD_AUTH_REPORT_DIR" => nil, "ADD_AUTH_RSPEC_MAIN" => nil},
        RbConfig.ruby, Gem.bin_path("rspec-core", "rspec"), "--options", File::NULL,
        "--require", configuration, file, "--format", "progress", **options)
    end
  end

  it "rejects an empty suite instead of reporting a successful CI result" do
    output, status = isolated_rspec('RSpec.describe("empty") {}')
    expect(output).to include("0 examples, 0 failures")
    expect(status.success?).to be(false)
  end

  it "rejects focused examples and groups in CI even if their assertion passes" do
    [
      'RSpec.describe("group") { it("focused", focus: true) { expect(true).to be(true) } }',
      'RSpec.describe("focused group", focus: true) { it("passes") { expect(true).to be(true) } }'
    ].each do |source|
      output, status = isolated_rspec(source)
      expect(output).to include("Focused RSpec metadata is forbidden in CI")
      expect(status.success?).to be(false)
    end
  end

  it "still permits local focus and a nonempty unfocused CI suite" do
    source = 'RSpec.describe("group") { it("passes") { expect(true).to be(true) } }'
    output, status = isolated_rspec(source)
    expect(output).to include("1 example, 0 failures")
    expect(status.success?).to be(true)
    output, status = isolated_rspec(source.sub('it("passes")', 'it("passes", focus: true)'), ci: nil)
    expect(status.success?).to be(true), output
  end

  it "reports actual autorun suites, preserves console counts and omits Capybara-only runners" do
    Dir.mktmpdir("add-auth-report-contract-") do |directory|
      configuration = File.expand_path("../support/rspec_configuration.rb", __dir__)
      environment = {"CI" => "true", "ADD_AUTH_REPORT_DIR" => directory, "ADD_AUTH_RSPEC_MAIN" => nil}
      command = [RbConfig.ruby, "-r", configuration, "-e"]
      output, status = Open3.capture2e(environment, *command, 'puts "manual browser runner"')
      expect(status.success?).to be(true), output
      expect(Dir[File.join(directory, "rspec-*.json")]).to be_empty
      {0 => "0 examples, 0 failures", 1 => "1 example, 0 failures"}.each do |count, summary|
        source = 'require "rspec/autorun"; RSpec.describe("inner") { ' + ((count == 1) ? 'it("passes") { expect(true).to be(true) }' : "") + " }"
        output, status = Open3.capture2e(environment, *command, source)
        expect(output).to include(summary)
        expect(status.success?).to eq(count == 1), output
        paths = Dir[File.join(directory, "rspec-*.json")]
        expect(paths.size).to eq(1)
        expect(JSON.parse(File.read(paths.first)).dig("summary", "example_count")).to eq(count)
        FileUtils.rm(paths)
      end
    end
  end
end

RSpec.describe AddAuthFixtureCache do
  around do |example|
    previous = ENV["ADD_AUTH_FIXTURE_CACHE"]
    Dir.mktmpdir("add-auth-cache-contract-") do |path|
      ENV["ADD_AUTH_FIXTURE_CACHE"] = path
      example.run
    end
  ensure
    ENV["ADD_AUTH_FIXTURE_CACHE"] = previous
  end

  def fetch(key, &block)
    described_class.fetch(namespace: "candidate", key: key, &block)
  end

  let(:key) { described_class.fingerprint([["source", "original"]]) }

  it "reuses verified immutable files but rebuilds corrupt or changed payloads" do
    builds = 0
    build = ->(path) {
      builds += 1
      File.write(File.join(path, "payload"), "verified")
    }
    path = fetch(key, &build)
    expect(fetch(key, &build)).to eq(path)
    expect(builds).to eq(1)
    File.write(File.join(path, "payload"), "corrupt")
    fetch(key, &build)
    expect(File.read(File.join(path, "payload"))).to eq("verified")
    expect(builds).to eq(2)
    changed = described_class.fingerprint([["source", "changed"]])
    expect(fetch(changed, &build)).not_to eq(path)
    expect(builds).to eq(3)
  end

  it "never reuses a partial build after interruption" do
    expect {
      fetch(key) { |path|
        File.write(File.join(path, "payload"), "partial")
        raise "interrupted"
      }
    }.to raise_error("interrupted")
    path = fetch(key) { |directory| File.write(File.join(directory, "payload"), "complete") }
    expect(File.read(File.join(path, "payload"))).to eq("complete")
  end

  it "serializes duplicate builders and does not return a partial artifact" do
    started, finish = Queue.new, Queue.new
    second = nil
    first = Thread.new do
      fetch(key) do |path|
        started << true
        finish.pop
        File.write(File.join(path, "payload"), "complete")
      end
    end
    Timeout.timeout(5) do
      started.pop
      second = Thread.new { fetch(key) { raise "duplicate build" } }
      finish << true
      expect(second.value).to eq(first.value)
      expect(File.read(File.join(second.value, "payload"))).to eq("complete")
    end
  ensure
    [first, second].compact.each { |thread| thread.kill if thread.alive? }
  end
end

RSpec.describe AddAuthTestReporting do
  it "requires a positive exact inner example count and zero failures" do
    expect(described_class.verify_examples!("19 examples, 0 failures\n", expected: 19)).to include("19 examples")
    ["0 examples, 0 failures\n", "18 examples, 0 failures\n", "19 examples, 1 failure\n"].each do |output|
      expect { described_class.verify_examples!(output, expected: 19) }.to raise_error(/needs 19 examples/)
    end
  end
end
