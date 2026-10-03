# frozen_string_literal: true

require "spec_helper"
require "tmpdir"
require "yaml"
require_relative "../../.github/scripts/ci_matrix"

RSpec.describe AddAuthCIMatrix do
  around do |example|
    Dir.mktmpdir("add-auth-ci-evidence-") do |path|
      @directory = path
      example.run
    end
  end

  def report(label, rails, examples)
    {"summary" => {"example_count" => examples.size, "failure_count" => 0, "pending_count" => 0, "errors_outside_of_examples_count" => 0},
     "examples" => examples, "execution" => {"main" => true, "invocation" => label, "ruby" => "3.3.11", "rails" => "#{rails.tr("_", ".")}.4", "turbo" => true, "ejected" => false}}
  end

  def row(id, mode: nil, negative: false, owner: "spec/providers/apple_form_post.rb")
    {"id" => id, "status" => "passed", "browser" => !mode.nil?, "browser_mode" => mode, "protocol_negative" => negative,
     "file_path" => "./#{owner}", "owner_file" => "./#{owner}"}
  end

  def write_shard(rails, suite)
    path = File.join(@directory, "#{rails}-#{suite}")
    FileUtils.mkdir_p(path)
    receipt = {"kind" => "ruby", "ruby" => "3.3", "rails" => rails, "suite" => suite, "sha" => "head", "source" => "source",
               "run_id" => "42", "attempt" => "2", "status" => "passed", "invocations" => []}
    described_class.plan("ruby", suite).each do |invocation|
      label = invocation.fetch("label")
      examples = if suite == "product" && %w[root ejected html html-ejected].include?(label)
        Array.new(13) { |i| row("js-#{i}", mode: "javascript") } +
          (label.start_with?("html") ? [] : Array.new(9) { |i| row("no-js-#{i}", mode: "no_js") })
      elsif suite == "providers"
        [row("handoff", owner: "spec/providers/apple_form_post.rb").merge("file_path" => "./spec/support/mobile_provider_journey.rb")] +
          ((label == "providers") ? Array.new(13) { |i| row("negative-#{i}", negative: true) } : [])
      else
        [row("#{label}-1")]
      end
      payload = report(label, rails, examples)
      payload["execution"]["turbo"] = invocation.fetch("env")["ADD_AUTH_TURBO"] != "0"
      payload["execution"]["ejected"] = invocation.fetch("env")["ADD_AUTH_EJECT_UI"] == "1"
      filename = "#{label}.json"
      File.write(File.join(path, filename), JSON.generate(payload))
      receipt["invocations"] << invocation.merge("reports" => [{"path" => filename, "sha256" => Digest::SHA256.file(File.join(path, filename)).hexdigest}])
    end
    File.write(File.join(path, "receipt.json"), JSON.generate(receipt))
    path
  end

  def complete_gate
    described_class::RAILS.product(described_class::SUITES.fetch("ruby")).each { |rails, suite| write_shard(rails, suite) }
  end

  def verify(**overrides)
    described_class.verify_gate!(kind: "ruby", ruby: "3.3", directory: @directory, sha: "head", source: "source", run_id: "42", attempt: "2", dependency_result: "success", **overrides)
  end

  def change_receipt(rails = "8_0", suite = "migration")
    path = File.join(@directory, "#{rails}-#{suite}", "receipt.json")
    payload = JSON.parse(File.read(path))
    yield payload
    File.write(path, JSON.generate(payload))
  end

  def change_report(label = "migration", suite = "migration")
    directory = File.join(@directory, "8_0-#{suite}")
    path = File.join(directory, "#{label}.json")
    payload = JSON.parse(File.read(path))
    yield payload
    File.write(path, JSON.generate(payload))
    change_receipt("8_0", suite) do |receipt|
      receipt.fetch("invocations").find { |row| row["label"] == label }.fetch("reports").first["sha256"] = Digest::SHA256.file(path).hexdigest
    end
  end

  it "accepts only the complete source/runtime/UI matrix, including shared provider journeys" do
    complete_gate
    expect(verify).to be(true)
  end

  it "excludes installed Bundler dependencies while detecting candidate source changes" do
    ignore_rules = File.read(File.expand_path("../../.gitignore", __dir__))
    Dir.chdir(@directory) do
      _output, status = Open3.capture2e("git", "init", "--quiet")
      expect(status.success?).to be(true)
      File.write(".gitignore", ignore_rules)
      File.write("candidate.rb", "original")
      _output, status = Open3.capture2e("git", "add", ".gitignore", "candidate.rb")
      expect(status.success?).to be(true)
      original = described_class.source_identity
      FileUtils.mkdir_p("vendor/bundle/gems")
      File.write("vendor/bundle/gems/dependency.rb", "runtime-specific dependency")
      expect(described_class.source_identity).to eq(original)
      File.write("candidate.rb", "changed")
      expect(described_class.source_identity).not_to eq(original)
      File.write("candidate.rb", "original")
      File.write("new_candidate.rb", "new source")
      expect(described_class.source_identity).not_to eq(original)
    end
  end

  %w[failure cancelled skipped].each do |status|
    it "rejects #{status} matrix results even if every artifact says passed" do
      complete_gate
      expect { verify(dependency_result: status) }.to raise_error(/did not complete successfully/)
    end
  end

  it "rejects missing and duplicate shards" do
    complete_gate
    path = File.join(@directory, "8_0-migration")
    FileUtils.cp_r(path, File.join(@directory, "duplicate"))
    expect { verify }.to raise_error(/Missing or duplicate/)
    FileUtils.rm_rf(File.join(@directory, "duplicate"))
    FileUtils.rm_rf(path)
    expect { verify }.to raise_error(/Missing or duplicate/)
  end

  %w[sha source run_id attempt status ruby].each do |field|
    it "rejects a shard with stale or foreign #{field}" do
      complete_gate
      change_receipt { |row| row[field] = "wrong" }
      expect { verify }.to raise_error(/foreign CI shard/)
    end
  end

  it "rejects a successful-looking shard that omitted an invocation" do
    complete_gate
    change_receipt { |row| row.fetch("invocations").pop }
    expect { verify }.to raise_error(/invocation schedule/)
  end

  it "rejects an empty or failed inner runner even when the outer example passed" do
    complete_gate
    path = File.join(@directory, "8_0-migration", "inner.json")
    inner = report("migration", "8_0", [])
    inner["execution"]["main"] = false
    File.write(path, JSON.generate(inner))
    change_receipt do |receipt|
      receipt.fetch("invocations").first.fetch("reports") << {"path" => "inner.json", "sha256" => Digest::SHA256.file(path).hexdigest}
    end
    expect { verify }.to raise_error(/empty/)
  end

  %w[failure_count pending_count errors_outside_of_examples_count].each do |field|
    it "rejects RSpec evidence with #{field}" do
      complete_gate
      change_report { |report| report.fetch("summary")[field] = 1 }
      expect { verify }.to raise_error(/failed, pending, empty/)
    end
  end

  it "rejects altered reports and duplicate outer executions" do
    complete_gate
    path = File.join(@directory, "8_0-migration", "migration.json")
    File.write(path, File.read(path) + "\n")
    expect { verify }.to raise_error(/checksum differs/)
    change_receipt do |receipt|
      reports = receipt.fetch("invocations").first.fetch("reports")
      reports.first["sha256"] = Digest::SHA256.file(path).hexdigest
      reports << reports.first.dup
    end
    expect { verify }.to raise_error(/duplicate outer/)
  end

  it "rejects omitted browser journeys and no-JS repeated in the ordinary-JS partition" do
    complete_gate
    change_report("html", "product") do |report|
      report.fetch("examples").last["browser_mode"] = "no_js"
    end
    expect { verify }.to raise_error(/Ordinary-JS partition/)
  end

  it "rejects ejected provider coverage that loses a shared handoff example" do
    complete_gate
    change_report("providers-ejected", "providers") do |report|
      report.fetch("examples").first["id"] = "unrelated"
    end
    expect { verify }.to raise_error(/provider UI coverage/)
  end

  it "keeps the exact required check names, isolated full matrix, profile caches and pinned actions" do
    workflow = YAML.load_file(File.expand_path("../../.github/workflows/ci.yml", __dir__))
    jobs = workflow.fetch("jobs")
    product = jobs.fetch("test")
    matrix = product.fetch("strategy").fetch("matrix")
    expect(matrix.fetch("ruby")).to eq(described_class::RUBIES)
    expect(matrix.fetch("rails")).to eq(described_class::RAILS)
    expect(matrix.fetch("suite")).to eq(described_class::SUITES.fetch("ruby"))
    expect(jobs.fetch("postgres-shards").dig("strategy", "matrix", "suite")).to eq(described_class::SUITES.fetch("postgres"))
    expect(jobs.fetch("postgres-shards").dig("strategy", "matrix", "rails")).to eq(described_class::RAILS)
    expect(jobs.fetch("ruby-gate").fetch("name")).to eq("Ruby ${{ matrix.ruby }}")
    expect(jobs.fetch("postgres").fetch("name")).to eq("PostgreSQL")
    expect(jobs.fetch("audit").fetch("name")).to eq("Dependency audit")
    {"ruby-gate" => "test", "postgres" => "postgres-shards"}.each do |gate, dependency|
      expect(jobs.fetch(gate).fetch("needs")).to eq(dependency)
      expect(jobs.fetch(gate).fetch("if")).to eq("always()")
      expect(jobs.fetch(gate).dig("env", "ADD_AUTH_CI_DEPENDENCY_RESULT")).to eq("${{ needs.#{dependency}.result }}")
    end
    %w[test postgres-shards].each do |name|
      job = jobs.fetch(name)
      expect(job.dig("env", "BUNDLE_GEMFILE")).to include("matrix.profile", "matrix.rails")
      expect(job.dig("strategy", "fail-fast")).to be(false)
      expect(job.fetch("steps").find { |step| step["uses"]&.start_with?("ruby/setup-ruby@") }.dig("with", "bundler-cache")).to be(true)
    end
    expect(workflow.dig("concurrency", "cancel-in-progress")).to be(true)
    expect(workflow.fetch("permissions")).to eq("contents" => "read")
    jobs.each_value do |job|
      job.fetch("steps").each do |step|
        expect(step.fetch("uses")).to match(/@[0-9a-f]{40}\z/) if step["uses"]
        if step["uses"]&.start_with?("actions/upload-artifact@")
          expect(step.dig("with", "archive")).to be(true)
          expect(step.dig("with", "if-no-files-found")).to eq("error")
        elsif step["uses"]&.start_with?("actions/download-artifact@")
          expect(step.dig("with", "merge-multiple")).to be(false)
          expect(step.dig("with", "digest-mismatch")).to eq("error")
        end
      end
    end
  end
end
