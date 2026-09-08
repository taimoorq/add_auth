# frozen_string_literal: true

# Explicit opt-in suite; run with gemfiles/operations.gemfile. Its filename
# keeps optional service dependencies out of the default RSpec matrix.
require "rails_helper"
require "socket"
require "tmpdir"
require "open3"
require "redis"
require "sidekiq/api"
require_relative "../support/local_smtp"

RSpec.describe "Local operational acceptance", database: true do
  def eventually
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 45
    loop do
      return if yield
      raise "local service did not reach its expected state" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      sleep 0.05
    end
  end

  def stop_process(pid)
    return unless pid
    Process.kill("TERM", pid)
    Timeout.timeout(10) { Process.wait(pid) }
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  rescue Timeout::Error
    Process.kill("KILL", pid)
    Process.wait(pid)
  end

  def start_redis
    @redis_pid = Process.spawn("redis-server", "--bind", "127.0.0.1", "--port", @redis_port.to_s,
      "--save", "", "--appendonly", "yes", "--appendfsync", "always", "--dir", @directory,
      out: File::NULL, err: File::NULL)
    eventually do
      Redis.new(url: @url).ping == "PONG"
    rescue Redis::BaseError
      false
    end
  end

  def start_worker
    @worker_pid = Process.spawn({"ADD_AUTH_LOCAL_REDIS_PORT" => @redis_port.to_s,
                                "ADD_AUTH_LOCAL_SMTP_PORT" => @smtp.port.to_s},
      RbConfig.ruby, Gem.bin_path("sidekiq", "sidekiq"), "-r", File.expand_path("worker.rb", __dir__),
      "-e", "test", "-c", "1", "-q", "default", "-t", "2",
      out: File.join(@directory, "worker.log"), err: [:child, :out])
    eventually { Sidekiq::ProcessSet.new.size == 1 }
  end

  around do |example|
    Dir.mktmpdir("add-auth-local-acceptance-") do |directory|
      @directory = directory
      socket = TCPServer.new("127.0.0.1", 0)
      @redis_port = socket.addr[1]
      socket.close
      @url = "redis://127.0.0.1:#{@redis_port}/0"
      start_redis
      queue_config = Sidekiq::Config.new
      queue_config.redis = {url: @url}
      pool = queue_config.redis_pool
      @smtp = LocalSMTP.new
      @messages, @attempts = @smtp.messages, @smtp.attempts
      Sidekiq::Client.via(pool) { example.run }
    ensure
      ActiveJob::Base.queue_adapter = :test
      stop_process(@worker_pid)
      stop_process(@redis_pid)
      pool&.shutdown(&:close)
      @smtp&.close
      @worker_pid = @redis_pid = nil
    end
  end

  it "shares atomic cache counters between independent Ruby processes" do
    script = <<~RUBY
      require "active_support"
      require "active_support/cache"
      require "redis"
      cache = ActiveSupport::Cache::RedisCacheStore.new(url: ENV.fetch("ADD_AUTH_LOCAL_REDIS"))
      20.times { puts cache.increment("add_auth:local-test:counter", 1, expires_in: 360, initial: 0) }
    RUBY
    workers = 2.times.map do
      Thread.new { Open3.capture3({"ADD_AUTH_LOCAL_REDIS" => @url}, RbConfig.ruby, "-e", script) }
    end
    results = workers.map(&:value)
    expect(results.all? { |_, _, status| status.success? }).to be(true)
    expect(results.flat_map { |out, _, _| out.lines.map(&:to_i) }.sort).to eq((1..40).to_a)
    expect(Redis.new(url: @url).ttl("add_auth:local-test:counter")).to be_between(300, 360)
  end

  it "recovers queued delivery after Redis and worker restarts and retries SMTP with the same issuance" do
    user = User.create!(email_address: "local-only@example.test", password: "correct-password")
    service = AddAuth::Rails::Runtime.email
    service.issue(identifier: user.email_address)
    record = AddAuthSignInToken.last
    original_digest = record.digest
    ActiveJob::Base.queue_adapter = :sidekiq
    AddAuth::EmailDeliveryJob.perform_later(record.id)
    expect(Sidekiq::Queue.new.size).to eq(1)
    stop_process(@redis_pid)
    @redis_pid = nil
    start_redis
    expect(Sidekiq::Queue.new.size).to eq(1)
    @smtp.reject_next = true
    start_worker
    eventually { @attempts.size >= 1 }
    eventually { record.reload.delivered_at.present? }
    expect(@attempts.size).to eq(2)
    expect(@messages.size).to eq(1)
    expect(record.digest).to eq(original_digest)
    expect(record.delivery_payload).to be_nil
    expect(AddAuthSignInToken.count).to eq(1)
    stop_process(@worker_pid)
    @worker_pid = nil
    # A new worker sees the same durable completed state and suppresses replay.
    AddAuth::EmailDeliveryJob.perform_later(record.id)
    start_worker
    eventually { Sidekiq::Queue.new.size.zero? && Sidekiq::WorkSet.new.size.zero? }
    expect(@messages.size).to eq(1)
  end
end
