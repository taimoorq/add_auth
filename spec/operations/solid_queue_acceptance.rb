# frozen_string_literal: true

require "rails"
require "rails/generators"
require "timeout"
require_relative "../support/isolated_host"
require_relative "../support/local_smtp"

RSpec.describe "Solid Queue in a separate database" do
  def stop(pid)
    return unless pid
    Process.kill("TERM", pid)
    Timeout.timeout(15) { Process.wait(pid) }
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  rescue Timeout::Error
    Process.kill("KILL", pid)
    Process.wait(pid)
  end

  it "recovers committed mail after enqueue failure and worker restart without changing issuance" do
    Dir.mktmpdir("add-auth-solid-queue-") do |directory|
      smtp = LocalSMTP.new
      host = IsolatedHost.new(directory)
      artifact = ENV["ADD_AUTH_OPERATIONS_GEM"] || IsolatedHost.candidate(directory)
      host.install(artifact, label: "package", extra_gems: ["solid_queue"])
      host.run("generate", "authentication")
      host.run("generate", "add_auth:email_link")
      host.run("generate", "solid_queue:install")
      host.configure
      File.write(File.join(host.root, "config/database.yml"), <<~YAML)
        test:
          primary:
            adapter: sqlite3
            database: storage/test.sqlite3
            timeout: 10000
          queue:
            adapter: sqlite3
            database: storage/queue.sqlite3
            migrations_paths: db/queue_migrate
            timeout: 10000
      YAML
      File.open(File.join(host.root, "config/environments/test.rb"), "a") do |file|
        file.puts "Rails.application.config.solid_queue.connects_to = { database: { writing: :queue } }"
      end
      File.write(File.join(host.root, "config/queue.yml"), <<~YAML)
        test:
          dispatchers:
            - polling_interval: 0.1
              batch_size: 100
          workers:
            - queues: "*"
              threads: 1
              processes: 1
              polling_interval: 0.1
      YAML
      File.open(File.join(host.root, "config/initializers/add_auth.rb"), "a") do |file|
        file.puts <<~RUBY
          ActiveJob::Base.queue_adapter = :solid_queue
          ActionMailer::Base.delivery_method = :smtp
          ActionMailer::Base.smtp_settings = {address: "127.0.0.1", port: #{smtp.port},
            enable_starttls_auto: false, open_timeout: 2, read_timeout: 2}
        RUBY
      end
      host.run("db:prepare")
      expect(host.runner(<<~RUBY)).to include("durable handoff verified")
        abort "queue shares authentication pool" if SolidQueue::Record.connection_pool.equal?(User.connection_pool)
        abort "authentication pools differ" unless [Session, AddAuthSignInToken].all? { |model| model.connection_pool.equal?(User.connection_pool) }
        user = User.create!(email_address: "solid-queue@example.test", password: "correct-password")
        runtime = AddAuth::Rails::Runtime
        # A transaction rollback cannot leave a deliverable proof.
        rollback = -> { raise ActiveRecord::Rollback }
        AddAuthSignInToken.before_create(rollback)
        runtime.email.issue(identifier: user.email_address)
        AddAuthSignInToken.skip_callback(:create, :before, rollback)
        abort "rolled back proof survived" unless AddAuthSignInToken.count.zero?
        runtime.email.issue(identifier: user.email_address)
        record = AddAuthSignInToken.last
        File.write(Rails.root.join("tmp/digest"), record.digest)
        # Exercise Active Job's real enqueue-error contract after the outbox
        # has committed, then restore the actual separate-database adapter.
        adapter = ActiveJob::Base.queue_adapter
        declining = Object.new
        def declining.enqueue(job) = raise ActiveJob::EnqueueError, "local rejection"
        def declining.enqueue_at(job, time) = enqueue(job)
        ActiveJob::Base.queue_adapter = declining
        Rails.application.load_tasks
        begin
          Rake::Task["add_auth:deliver_pending"].invoke
          abort "declined sweep reported success"
        rescue AddAuth::Error
          abort "failed enqueue erased outbox" unless record.reload.delivery_payload && !record.delivered_at
        ensure
          ActiveJob::Base.queue_adapter = adapter
        end
        Rake::Task["add_auth:deliver_pending"].reenable
        Rake::Task["add_auth:deliver_pending"].invoke
        abort "separate queue lost handoff" unless SolidQueue::ReadyExecution.count == 1
        puts "durable handoff verified"
      RUBY
      smtp.reject_next = true
      worker = host.spawn("bin/jobs", "start", "--skip-recurring")
      Timeout.timeout(45) { sleep 0.05 until smtp.messages.size == 1 }
      expect(host.runner(<<~RUBY)).to include("delivered after retry")
        record = AddAuthSignInToken.last
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
        until record.reload.delivered_at
          abort "missing delivery receipt" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          sleep 0.05
        end
        abort "retry minted another proof" unless AddAuthSignInToken.count == 1 && record.digest == File.read(Rails.root.join("tmp/digest"))
        abort "delivered ciphertext retained" unless record.delivery_payload.nil?
        abort "retry exhausted" unless SolidQueue::FailedExecution.count.zero?
        puts "delivered after retry"
      RUBY
      expect(smtp.attempts.size).to eq(2)
      stop(worker)
      worker = nil
      host.runner("AddAuth::EmailDeliveryJob.perform_later(AddAuthSignInToken.last.id)")
      worker = host.spawn("bin/jobs", "start", "--skip-recurring", log: "restarted-worker.log")
      expect(host.runner(<<~RUBY)).to include("restart suppressed replay")
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
        until SolidQueue::Job.where(finished_at: nil).none?
          abort "restarted worker did not drain" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          sleep 0.1
        end
        puts "restart suppressed replay"
      RUBY
      expect(smtp.messages.size).to eq(1)
    ensure
      stop(worker)
      smtp&.close
    end
  end
end
