# frozen_string_literal: true

require "json"
require "open3"

module AddAuthReleaseGate
  REQUIRED_CHECKS = ["Ruby 3.3", "Ruby 3.4", "Ruby 4.0", "PostgreSQL", "Dependency audit"].freeze

  module_function

  def verify!(sha:, branch:, runs:, checks:)
    candidates = runs.select { |run| run["head_sha"] == sha && run["head_branch"] == branch && %w[push workflow_dispatch].include?(run["event"]) }
    latest = candidates.max_by { |run| [run.fetch("run_number"), run.fetch("run_attempt", 1)] }
    raise "Release commit needs a successful default-branch CI run" unless latest && latest["status"] == "completed" && latest["conclusion"] == "success"
    verify_checks!(sha: sha, run: latest, checks: checks)
  end

  def verify_checks!(sha:, run:, checks:)
    REQUIRED_CHECKS.each do |name|
      job = checks.select { |check|
        check["name"] == name && check["head_sha"] == sha &&
          check.dig("app", "id") == 15_368 && check.dig("check_suite", "id") == run["check_suite_id"]
      }.max_by { |check| check.fetch("id") }
      raise "Release commit is missing a successful required check: #{name}" unless job && job["status"] == "completed" && job["conclusion"] == "success"
    end
    true
  end

  def verify_pr!(sha:, branch:, repo:, pr:, release_tree:, head_tree:, base_ancestor:, runs:, checks:)
    unless pr["merged"] == true && pr["merge_commit_sha"] == sha && pr.dig("base", "ref") == branch &&
        pr.dig("base", "repo", "full_name") == repo && pr.dig("head", "repo", "full_name") == repo
      raise "Release commit needs its merged same-repository PR"
    end
    raise "Release tree differs from tested PR head" unless !release_tree.to_s.empty? && release_tree == head_tree && base_ancestor
    head = pr.fetch("head").fetch("sha")
    candidates = runs.select { |run| run["head_sha"] == head && run["event"] == "pull_request" && run.dig("head_repository", "full_name") == repo }
    latest = candidates.max_by { |run| [run.fetch("run_number"), run.fetch("run_attempt", 1)] }
    raise "Merged PR needs its latest CI run successful" unless latest && latest["status"] == "completed" && latest["conclusion"] == "success"
    verify_checks!(sha: head, run: latest, checks: checks)
  end

  def api(path)
    JSON.parse(command("gh", "api", path))
  end

  def pages(path, key)
    JSON.parse(command("gh", "api", "--paginate", "--slurp", path)).flat_map { |page| page.fetch(key) }
  end

  def runs_for(repo, sha)
    pages("repos/#{repo}/actions/workflows/ci.yml/runs?head_sha=#{sha}&per_page=100", "workflow_runs")
  end

  def checks_for(repo, sha)
    pages("repos/#{repo}/commits/#{sha}/check-runs?filter=all&per_page=100", "check_runs")
  end

  def verify_provenance!(repo:, sha:, branch:)
    runs = runs_for(repo, sha)
    if runs.any? { |run| run["head_branch"] == branch && %w[push workflow_dispatch].include?(run["event"]) }
      return verify!(sha: sha, branch: branch, runs: runs, checks: checks_for(repo, sha))
    end
    prs = JSON.parse(command("gh", "api", "--paginate", "--slurp", "repos/#{repo}/commits/#{sha}/pulls?per_page=100")).flatten
    candidates = prs.select { |pr| pr["merge_commit_sha"] == sha && pr.dig("base", "ref") == branch }
    raise "Release commit needs one associated merged PR" unless candidates.size == 1
    pr = api("repos/#{repo}/pulls/#{candidates.first.fetch("number")}")
    head = pr.fetch("head").fetch("sha")
    base = pr.fetch("base").fetch("sha")
    comparison = api("repos/#{repo}/compare/#{base}...#{head}")
    verify_pr!(sha: sha, branch: branch, repo: repo, pr: pr,
      release_tree: api("repos/#{repo}/git/commits/#{sha}").fetch("tree").fetch("sha"),
      head_tree: api("repos/#{repo}/git/commits/#{head}").fetch("tree").fetch("sha"),
      base_ancestor: comparison.dig("merge_base_commit", "sha") == base,
      runs: runs_for(repo, head), checks: checks_for(repo, head))
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
    verify_provenance!(repo: repo, sha: sha, branch: branch)
    puts "Release provenance verified for #{sha}"
  end
end

AddAuthReleaseGate.run! if $PROGRAM_NAME == __FILE__
