# frozen_string_literal: true

require "rails"
require "rails/generators"
require "socket"
require "timeout"
require "uri"
require_relative "../support/isolated_host"

# Records the upstream store's missing-row race so support cannot be inferred
# from its sequential increment API. No app/authentication data is used.
RSpec.describe "Solid Cache rate-counter suitability" do
  it "demonstrates a lost initial increment on PostgreSQL" do
    url = ENV.fetch("ADD_AUTH_CACHE_TEST_URL")
    parsed = URI.parse(url)
    unless %w[postgres postgresql].include?(parsed.scheme) && parsed.path == "/add_auth_test" &&
        %w[localhost 127.0.0.1].include?(parsed.host)
      raise "ADD_AUTH_CACHE_TEST_URL must target a local disposable add_auth_test database"
    end
    Dir.mktmpdir("add-auth-cache-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: ["solid_cache", "pg"])
      host.run("generate", "solid_cache:install")
      File.write(File.join(host.root, "config/database.yml"), <<~YAML)
        test:
          primary:
            adapter: sqlite3
            database: storage/test.sqlite3
          cache:
            url: #{url}
            migrations_paths: db/cache_migrate
      YAML
      File.open(File.join(host.root, "config/environments/test.rb"), "a") do |file|
        file.puts "Rails.application.config.solid_cache.connects_to = { database: { writing: :cache } }"
      end
      host.run("db:prepare")
      key = "add_auth:acceptance:#{SecureRandom.hex(16)}"
      gate = TCPServer.new("127.0.0.1", 0)
      script = File.join(directory, "cache-race.rb")
      File.write(script, <<~RUBY)
        require "socket"
        # Both real processes have completed the missing-row SELECT FOR UPDATE
        # before either writes. Existing-row locking cannot protect an absent row.
        SolidCache::Entry.singleton_class.prepend(Module.new do
          def lock_and_write(key, &block)
            super(key) do |value|
              if value.nil?
                socket = TCPSocket.new("127.0.0.1", #{gate.addr[1]})
                socket.puts "ready"
                raise "missing release" unless socket.gets == "go\\n"
                socket.close
              end
              block.call(value)
            end
          end
        end)
        cache = SolidCache::Store.new
        puts "counter=\#{cache.increment(#{key.inspect}, 1, expires_in: 360, initial: 0)}"
      RUBY
      pids = 2.times.map { |index| host.spawn("bin/rails", "runner", script, log: "counter-#{index}.log") }
      Timeout.timeout(20) do
        sockets = 2.times.map { gate.accept }
        expect(sockets.map(&:gets)).to eq(["ready\n", "ready\n"])
        sockets.each { |socket| socket.puts "go" }
        sockets.each(&:close)
        pids.each { |pid| expect(Process.wait2(pid).last.success?).to be(true) }
      end
      values = 2.times.map { |index| File.read(File.join(directory, "counter-#{index}.log"))[/counter=(\d+)/, 1]&.to_i }
      expect(values).to eq([1, 1])
      expect(host.runner(<<~RUBY)).to include("lost increment verified")
        cache = SolidCache::Store.new
        abort "unexpected counter" unless cache.read(#{key.inspect}) == 1
        cache.delete(#{key.inspect})
        require "add_auth/rails/rate_limit_cache"
        begin
          AddAuth::Rails::RateLimitCache.validate!(cache)
          abort "unsafe cache accepted"
        rescue AddAuth::Error => error
          abort "unhelpful adapter rejection" unless error.message.include?("separate atomic store")
        end
        puts "lost increment verified"
      RUBY
    rescue Timeout::Error
      2.times { |index| warn File.read(File.join(directory, "counter-#{index}.log")) }
      raise
    ensure
      gate&.close
      pids&.each do |pid|
        Process.kill("TERM", pid)
        Process.wait(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end
  end
end
