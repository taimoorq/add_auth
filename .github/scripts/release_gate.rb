# frozen_string_literal: true

require "json"
require "open3"

module AddAuthReleaseGate
  REQUIRED_CHECKS = ["Ruby 3.3", "Ruby 3.4", "Ruby 4.0", "PostgreSQL", "Dependency audit"].freeze
  module_function

  def verify!(sha:, branch:, runs:, checks:)
    candidates = runs.select { |run| run["head_sha"] == sha && run["head_branch"] == branch && run["event"] == "push" }
    latest = candidates.max_by { |run| [run.fetch("run_number"), run.fetch("run_attempt", 1)] }
    raise "Release commit needs a successful default-branch CI run" unless latest && latest["status"] == "completed" && latest["conclusion"] == "success"
    REQUIRED_CHECKS.each do |name|
      job = checks.select { |check| check["name"] == name && check["head_sha"] == sha &&
        check.dig("app", "id") == 15_368 && check.dig("check_suite", "id") == latest["check_suite_id"] }.max_by { |check| check.fetch("id") }
      raise "Release commit is missing a successful required check: #{name}" unless job && job["status"] == "completed" && job["conclusion"] == "success"
    end
    true
  end

  def command(*arguments)
    output, status = Open3.capture2(*arguments)
    raise "Release provenance command failed" unless status.success?
    output.strip
  end

  def run!
    repo = ENV.fetch("GITHUB_REPOSITORY")
    sha = command("git", "rev-parse", "HEAD")
    branch = JSON.parse(command("gh", "api", "repos/#{repo}")).fetch("default_branch")
    command("git", "merge-base", "--is-ancestor", sha, "origin/#{branch}")
    require_relative "../../lib/add_auth/version"
    raise "Release tag does not match the gem version" unless ENV.fetch("GITHUB_REF_NAME") == "v#{AddAuth::VERSION}"
    runs = JSON.parse(command("gh", "api", "--paginate", "--slurp", "repos/#{repo}/actions/workflows/ci.yml/runs?head_sha=#{sha}&event=push&per_page=100"))
      .flat_map { |page| page.fetch("workflow_runs") }
    checks = JSON.parse(command("gh", "api", "--paginate", "--slurp", "repos/#{repo}/commits/#{sha}/check-runs?filter=latest&per_page=100"))
      .flat_map { |page| page.fetch("check_runs") }
    verify!(sha: sha, branch: branch, runs: runs, checks: checks)
    puts "Release provenance verified for #{sha}"
  end
end

AddAuthReleaseGate.run! if $PROGRAM_NAME == __FILE__
