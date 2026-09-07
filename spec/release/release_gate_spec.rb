# frozen_string_literal: true

require "spec_helper"
require_relative "../../.github/scripts/release_gate"

RSpec.describe LatchkeyReleaseGate do
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
end
