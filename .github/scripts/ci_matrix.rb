# frozen_string_literal: true

require "json"
require "digest"
require "open3"

module AddAuthCIMatrix
  RUBIES = %w[3.3 3.4 4.0].freeze
  RAILS = %w[8_0 8_1].freeze
  SUITES = {"ruby" => %w[product migration providers], "postgres" => %w[stores migration native keys]}.freeze
  BASELINES = %w[0.2.1 0.2.2 0.3.0 0.4.0].freeze

  module_function

  def invocation(label, args, env = {})
    {"label" => label, "args" => args, "env" => env}
  end

  def plan(kind, suite)
    raise "Unknown CI shard" unless SUITES.fetch(kind).include?(suite)
    case [kind, suite]
    when ["ruby", "product"]
      [invocation("root", []), invocation("confirmation-upgrade", ["spec/upgrade/confirmation_policy.rb"]),
        invocation("ejected", ["spec/system"], "ADD_AUTH_EJECT_UI" => "1"),
        invocation("html", ["spec/system", "--tag", "browser_mode:javascript"], "ADD_AUTH_TURBO" => "0"),
        invocation("html-ejected", ["spec/system", "--tag", "browser_mode:javascript"], "ADD_AUTH_TURBO" => "0", "ADD_AUTH_EJECT_UI" => "1")] +
        BASELINES.map { |version| invocation("upgrade-#{version}", ["spec/upgrade/published_package.rb"], "ADD_AUTH_BASELINE_VERSION" => version) }
    when ["ruby", "migration"]
      [invocation("migration", Dir["spec/migration/*.rb"].sort),
        invocation("migration-ejected", %w[spec/migration/account_lifecycle.rb spec/migration/optional_confirmation.rb spec/generators/optional_confirmation_generator_spec.rb], "ADD_AUTH_EJECT_UI" => "1")]
    when ["ruby", "providers"]
      [invocation("providers", Dir["spec/providers/*.rb"].sort),
        invocation("providers-ejected", %w[spec/providers/google_sign_in.rb spec/providers/apple_form_post.rb spec/providers/microsoft_browser.rb spec/providers/apple_native_host.rb --tag ~protocol_negative], "ADD_AUTH_EJECT_UI" => "1")]
    when ["postgres", "stores"]
      [invocation("stores", %w[spec/add_auth/rails spec/requests])]
    when ["postgres", "migration"]
      [invocation("migration", %w[spec/migration/devise_source.rb spec/migration/account_adoption.rb spec/migration/source_bridge.rb spec/migration/account_lifecycle.rb spec/migration/optional_confirmation.rb spec/migration/backfill_checkpoint.rb spec/migration/compatible_rollback.rb]),
        invocation("migration-ejected", ["spec/migration/optional_confirmation.rb"], "ADD_AUTH_EJECT_UI" => "1"),
        invocation("external-enrollment", %w[spec/migration/external_enrollment.rb spec/generators/external_identities_generator_spec.rb])]
    when ["postgres", "native"]
      [invocation("native", ["spec/providers/apple_native.rb"])]
    when ["postgres", "keys"]
      [invocation("keys", ["spec/keys/authentication_tables.rb"])]
    end
  end

  def profile(kind, suite)
    return "providers_rails" if suite == "providers" || suite == "native"
    return "devise_rails" if suite == "migration"
    "rails"
  end

  def source_identity
    paths, status = Open3.capture2("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    raise "Cannot inventory the CI source" unless status.success?
    digest = Digest::SHA256.new
    paths.split("\0").sort.each do |path|
      next unless File.file?(path)
      content = File.binread(path)
      digest << path.bytesize.to_s << ":" << path << content.bytesize.to_s << ":" << content
    end
    digest.hexdigest
  end

  def valid_report!(report, ruby:, rails:)
    summary = report.fetch("summary")
    examples = report.fetch("examples")
    execution = report.fetch("execution")
    unless summary["example_count"].is_a?(Integer) && summary["example_count"].positive? &&
        %w[failure_count pending_count errors_outside_of_examples_count].all? { |key| summary[key] == 0 } &&
        examples.size == summary["example_count"] && examples.all? { |example| example["status"] == "passed" } &&
        execution.fetch("ruby").start_with?("#{ruby}.") && execution.fetch("rails").start_with?("#{rails.tr("_", ".")}.")
      raise "Incomplete, failed, pending, empty or wrong-runtime RSpec evidence"
    end
    true
  end

  def read_reports!(directory, rows, ruby:, rails:)
    raise "Missing RSpec execution reports" if rows.empty?
    rows.map do |row|
      path = File.expand_path(row.fetch("path"), directory)
      raise "Report path escapes its shard" unless path.start_with?(File.expand_path(directory) + File::SEPARATOR)
      raise "RSpec report checksum differs" unless Digest::SHA256.file(path).hexdigest == row.fetch("sha256")
      JSON.parse(File.read(path)).tap { |report| valid_report!(report, ruby: ruby, rails: rails) }
    end
  end

  def browser_ids(report, mode = nil)
    report.fetch("examples").select { |row| row["browser"] && (!mode || row["browser_mode"] == mode) }.map { |row| row.fetch("id") }.sort
  end

  def verify_browsers!(reports)
    root = reports.fetch("root")
    js, no_js = browser_ids(root, "javascript"), browser_ids(root, "no_js")
    raise "Missing browser mode metadata/coverage" unless js.size == 13 && no_js.size == 9 && browser_ids(root).size == 22
    raise "Ejected browser journeys differ" unless browser_ids(reports.fetch("ejected")) == (js + no_js).sort
    %w[html html-ejected].each do |label|
      raise "Ordinary-JS partition differs or repeats no-JS" unless browser_ids(reports.fetch(label)) == js && browser_ids(reports.fetch(label), "no_js").empty?
    end
  end

  def verify_shard!(receipt, directory:, ruby:, rails:, suite:, kind:, sha:, source:, run_id:, attempt:)
    expected = {"kind" => kind, "ruby" => ruby, "rails" => rails, "suite" => suite,
                "sha" => sha, "source" => source, "run_id" => run_id, "attempt" => attempt, "status" => "passed"}
    raise "Missing, stale, failed or foreign CI shard" unless expected.all? { |key, value| receipt[key] == value }
    planned = plan(kind, suite)
    executed = receipt.fetch("invocations")
    raise "Incomplete CI invocation schedule" unless executed.map { |row| row.slice("label", "args", "env") } == planned
    main_reports = executed.to_h do |row|
      reports = read_reports!(directory, row.fetch("reports"), ruby: ruby, rails: rails)
      main = reports.select { |report| report.dig("execution", "main") == true }
      raise "Missing or duplicate outer RSpec report" unless main.size == 1
      report = main.first
      expected_turbo = row.fetch("env")["ADD_AUTH_TURBO"] != "0"
      expected_ejected = row.fetch("env")["ADD_AUTH_EJECT_UI"] == "1"
      unless report.dig("execution", "invocation") == row.fetch("label") &&
          report.dig("execution", "turbo") == expected_turbo && report.dig("execution", "ejected") == expected_ejected
        raise "RSpec invocation/UI context differs"
      end
      [row.fetch("label"), report]
    end
    verify_browsers!(main_reports) if kind == "ruby" && suite == "product"
    if kind == "ruby" && suite == "providers"
      bundled = main_reports.fetch("providers").fetch("examples")
      ejected = main_reports.fetch("providers-ejected").fetch("examples")
      negatives = bundled.select { |row| row["protocol_negative"] }
      raise "Missing complete provider rejection tables" unless negatives.size == 13
      raise "Ejected UI repeats protocol-only negatives" if ejected.any? { |row| row["protocol_negative"] }
      expected_ids = bundled.select { |row| plan(kind, suite).last.fetch("args").include?(row.fetch("owner_file").delete_prefix("./")) && !row["protocol_negative"] }.map { |row| row.fetch("id") }.sort
      raise "Ejected provider UI coverage differs" unless ejected.map { |row| row.fetch("id") }.sort == expected_ids
    end
    true
  end

  def verify_gate!(kind:, ruby:, directory:, sha:, source:, run_id:, attempt:, dependency_result:)
    raise "Required CI matrix did not complete successfully" unless dependency_result == "success"
    expected = RAILS.product(SUITES.fetch(kind))
    paths = Dir[File.join(directory, "**/receipt.json")]
    receipts = paths.map { |path| [path, JSON.parse(File.read(path))] }
    keys = receipts.map { |_path, row| [row["rails"], row["suite"]] }
    raise "Missing or duplicate required CI shards" unless keys.sort == expected.sort
    receipts.each do |path, row|
      verify_shard!(row, directory: File.dirname(path), ruby: ruby, rails: row.fetch("rails"), suite: row.fetch("suite"), kind: kind,
        sha: sha, source: source, run_id: run_id, attempt: attempt)
    end
    true
  end

  def run_gate!
    kind, ruby, directory = ARGV
    raise "Unsupported aggregate gate" unless SUITES.key?(kind) && RUBIES.include?(ruby)
    sha, status = Open3.capture2("git", "rev-parse", "HEAD")
    raise "Cannot identify the candidate head" unless status.success?
    verify_gate!(kind: kind, ruby: ruby, directory: directory, sha: sha.strip, source: source_identity,
      run_id: ENV.fetch("GITHUB_RUN_ID"), attempt: ENV.fetch("GITHUB_RUN_ATTEMPT"),
      dependency_result: ENV.fetch("ADD_AUTH_CI_DEPENDENCY_RESULT"))
    puts "Verified every #{kind}/#{ruby} shard, invocation and nonempty RSpec result for #{sha.strip}"
  end
end

AddAuthCIMatrix.run_gate! if $PROGRAM_NAME == __FILE__
