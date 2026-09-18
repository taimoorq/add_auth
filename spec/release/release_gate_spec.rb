# frozen_string_literal: true

require "spec_helper"
require_relative "../../.github/scripts/release_gate"

RSpec.describe AddAuthReleaseGate do
  it "limits the owner-authorized transition to 0.5.0 and release infrastructure" do
    expect(described_class.transition_allowed?(version: "0.5.0", changed: described_class::TRANSITION_FILES)).to be(true)
    expect(described_class.transition_allowed?(version: "0.5.1", changed: described_class::TRANSITION_FILES)).to be(false)
    expect(described_class.transition_allowed?(version: "0.5.0", changed: [])).to be(false)
    %w[lib/add_auth/core/sessions.rb add_auth.gemspec Gemfile app/controllers/add_auth/sessions_controller.rb].each do |path|
      expect(described_class.transition_allowed?(version: "0.5.0", changed: described_class::TRANSITION_FILES + [path])).to be(false)
    end
  end
  let(:run) { {"head_sha" => "commit", "head_branch" => "master", "event" => "push", "status" => "completed", "conclusion" => "success", "run_number" => 10, "check_suite_id" => 1} }
  let(:checks) do
    described_class::REQUIRED_CHECKS.map.with_index do |name, index|
      {"name" => name, "head_sha" => "commit", "app" => {"id" => 15_368}, "check_suite" => {"id" => 1}, "id" => index,
       "status" => "completed", "conclusion" => "success"}
    end
  end
  def verify(runs: [run], jobs: checks)
    described_class.verify!(sha: "commit", branch: "master", runs: runs, checks: jobs)
  end

  it "accepts only a complete exact-commit default-branch CI run" do
    expect(verify).to be(true)
    %w[head_sha head_branch event status conclusion].each do |field|
      expect { verify(runs: [run.merge(field => "wrong")]) }.to raise_error(RuntimeError)
    end
  end

  it "rejects missing, foreign-suite, stale or failed checks" do
    checks.each_index do |index|
      expect { verify(jobs: checks.reject.with_index { |_, i| i == index }) }.to raise_error(RuntimeError)
      expect { verify(jobs: checks.map.with_index { |check, i| (i == index) ? check.merge("conclusion" => "failure") : check }) }.to raise_error(RuntimeError)
    end
    expect { verify(jobs: checks.map { |check| check.merge("check_suite" => {"id" => 2}) }) }.to raise_error(RuntimeError)
  end

  it "does not reuse an older successful run while a newer run is failing or pending" do
    %w[in_progress completed].each do |status|
      expect { verify(runs: [run, run.merge("run_number" => 11, "status" => status, "conclusion" => "failure")]) }.to raise_error(RuntimeError)
    end
  end

  it "accepts an explicit default-branch manual rerun" do
    expect(verify(runs: [run.merge("event" => "workflow_dispatch")])).to be(true)
  end

  it "does not fall back to PR evidence when an explicit default-branch run fails" do
    allow(described_class).to receive(:runs_for).with("owner/add_auth", "commit").and_return([run.merge("conclusion" => "failure")])
    allow(described_class).to receive(:checks_for).with("owner/add_auth", "commit").and_return(checks)
    expect(described_class).not_to receive(:command)
    expect { described_class.verify_provenance!(repo: "owner/add_auth", sha: "commit", branch: "master") }.to raise_error(/default-branch CI/)
  end

  describe "reusing merged PR evidence" do
    let(:repo) { "owner/add_auth" }
    let(:pr) do
      {"merged" => true, "merge_commit_sha" => "release",
       "base" => {"ref" => "master", "repo" => {"full_name" => repo}},
       "head" => {"sha" => "commit", "repo" => {"full_name" => repo}}}
    end
    let(:pr_run) { run.merge("event" => "pull_request", "head_repository" => {"full_name" => repo}) }

    def reuse(**overrides)
      described_class.verify_pr!(sha: "release", branch: "master", repo: repo, pr: pr,
        release_tree: "tree", head_tree: "tree", base_ancestor: true,
        runs: [pr_run], checks: checks, **overrides)
    end

    it "accepts the exact tree despite squash-merge changing the commit SHA" do
      expect(reuse).to be(true)
    end

    it "resolves the merged PR, immutable trees and CI through paginated API evidence" do
      allow(described_class).to receive(:runs_for).with(repo, "release").and_return([])
      allow(described_class).to receive(:runs_for).with(repo, "commit").and_return([pr_run])
      allow(described_class).to receive(:checks_for).with(repo, "commit").and_return(checks)
      allow(described_class).to receive(:command).with("gh", "api", "--paginate", "--slurp", "repos/#{repo}/commits/release/pulls?per_page=100")
        .and_return([[], [pr.merge("number" => 16)]].to_json)
      allow(described_class).to receive(:api).with("repos/#{repo}/pulls/16").and_return(pr.merge("base" => pr["base"].merge("sha" => "base")))
      allow(described_class).to receive(:api).with("repos/#{repo}/compare/base...commit").and_return("merge_base_commit" => {"sha" => "base"})
      %w[release commit].each do |sha|
        allow(described_class).to receive(:api).with("repos/#{repo}/git/commits/#{sha}").and_return("tree" => {"sha" => "tree"})
      end
      expect(described_class.verify_provenance!(repo: repo, sha: "release", branch: "master")).to be(true)
    end

    it "fails closed when the release has no associated PR" do
      allow(described_class).to receive(:runs_for).with(repo, "release").and_return([])
      allow(described_class).to receive(:command).with("gh", "api", "--paginate", "--slurp", "repos/#{repo}/commits/release/pulls?per_page=100").and_return("[[]]")
      expect { described_class.verify_provenance!(repo: repo, sha: "release", branch: "master") }.to raise_error(/one associated merged PR/)
    end

    it "rejects changed files, absent tree identity and a base not included in the PR head" do
      expect { reuse(head_tree: "other") }.to raise_error(/tree differs/)
      expect { reuse(head_tree: "", release_tree: "") }.to raise_error(/tree differs/)
      expect { reuse(base_ancestor: false) }.to raise_error(/tree differs/)
    end

    it "rejects unmerged, unrelated, wrong-target and foreign PRs" do
      [{"merged" => false}, {"merge_commit_sha" => "other"},
        {"base" => pr["base"].merge("ref" => "other")},
        {"base" => pr["base"].merge("repo" => {"full_name" => "other"})},
        {"head" => pr["head"].merge("repo" => {"full_name" => "other"})}].each do |change|
        expect { reuse(pr: pr.merge(change)) }.to raise_error(/merged same-repository PR/)
      end
    end

    it "requires the latest successful run of this PR head in this repository" do
      expect { reuse(runs: []) }.to raise_error(/latest CI/)
      %w[head_sha event status conclusion].each do |field|
        expect { reuse(runs: [pr_run.merge(field => "wrong")]) }.to raise_error(/latest CI/)
      end
      expect { reuse(runs: [pr_run.merge("head_repository" => {"full_name" => "foreign"})]) }.to raise_error(/latest CI/)
      %w[in_progress completed].each do |status|
        expect { reuse(runs: [pr_run, pr_run.merge("run_number" => 11, "status" => status, "conclusion" => "failure")]) }.to raise_error(/latest CI/)
      end
      expect { reuse(runs: [pr_run, pr_run.merge("run_attempt" => 2, "conclusion" => "failure")]) }.to raise_error(/latest CI/)
    end

    it "requires every successful check from the selected Actions suite and head" do
      checks.each_index do |index|
        expect { reuse(checks: checks.reject.with_index { |_, i| i == index }) }.to raise_error(/missing a successful/)
      end
      [{"head_sha" => "other"}, {"check_suite" => {"id" => 2}},
        {"app" => {"id" => 1}}, {"status" => "queued"}, {"conclusion" => "skipped"}].each do |change|
        expect { reuse(checks: checks.map { |check| check.merge(change) }) }.to raise_error(/missing a successful/)
      end
    end
  end
end
