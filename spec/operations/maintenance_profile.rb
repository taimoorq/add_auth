# frozen_string_literal: true

# Repeatable local workload measurement, not a production capacity promise.
require "rails_helper"
require "rake"

RSpec.describe "Bounded authentication maintenance profile", database: true do
  it "bounds session reads and drains expired history in restartable passes" do
    user = User.create!(email_address: "load@example.test", password: "correct-password")
    other = User.create!(email_address: "other@example.test", password: "correct-password")
    now = Time.current
    records = 5000.times.map do |index|
      {user_id: index.even? ? user.id : other.id, authenticated_with: "password", authenticated_at: now,
       token_digest: "profile-#{index}", expires_at: now + 3600, last_seen_at: now, created_at: now, updated_at: now}
    end
    Session.insert_all!(records)
    current = Session.where(user_id: user.id).first
    queries, loaded = [], 0
    read = ->(*args) { queries << args.last[:sql] if args.last[:sql].match?(/\ASELECT/i) }
    rows = ->(*args) { loaded += args.last[:record_count] if args.last[:class_name] == "Session" }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    page = nil
    ActiveSupport::Notifications.subscribed(read, "sql.active_record") do
      ActiveSupport::Notifications.subscribed(rows, "instantiation.active_record") do
        page = AddAuth::Rails::Runtime.sessions.list_page(user: user, current_session_id: current.id)
      end
    end
    page_ms = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
    expect(page.entries.size).to eq(51)
    expect(loaded).to be <= 52
    expect(queries.size).to be <= 3
    expect(page.next_cursor).not_to be_nil
    expect(page.entries.map(&:id) - Session.where(user_id: user.id).pluck(:id)).to be_empty

    expired = records.first(1200).each_with_index.map do |attributes, index|
      attributes.merge(token_digest: "expired-#{index}", expires_at: now - 3600, last_seen_at: now - 7200)
    end
    Session.insert_all!(expired)
    options = AddAuth.configuration.maintenance
    previous = [options.batch_size, options.session_retention]
    options.batch_size, options.session_retention = 100, 0
    Rails.application.load_tasks unless Rake::Task.task_defined?("add_auth:deliver_pending")
    task = Rake::Task["add_auth:deliver_pending"]
    passes, timings = [], []
    listener = ->(*args) { passes << args.last.dup }
    ActiveSupport::Notifications.subscribed(listener, "maintenance.add_auth") do
      13.times do
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        task.reenable
        task.invoke
        timings << (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
      end
    end
    expect(passes.map { |pass| pass[:session_deleted] }).to eq([100] * 12 + [0])
    expect(Session.count).to eq(5000)
    puts JSON.generate(profile: "maintenance", database: Session.connection.adapter_name,
      active_sessions: 5000, expired_sessions: 1200, page_queries: queries.size, page_rows_loaded: loaded,
      page_ms: page_ms.round(2), passes_to_drain: 12, batch_size: 100,
      pass_ms_min: timings.min.round(2), pass_ms_max: timings.max.round(2))
  ensure
    options.batch_size, options.session_retention = previous if previous
  end
end
