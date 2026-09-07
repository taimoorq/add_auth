# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Shared rate-limit counters" do
  let(:runtime) { AddAuth::Rails::Runtime }

  around do |example|
    previous = AddAuth.configuration.rate_limit_store
    AddAuth.configuration.rate_limit_store = ActiveSupport::Cache::MemoryStore.new
    example.run
  ensure
    AddAuth.configuration.rate_limit_store = previous
  end

  it "admits at most the budget across competing workers" do
    ready, go = Queue.new, Queue.new
    threads = 20.times.map do
      Thread.new do
        ready << true
        go.pop
        runtime.limit(key: "shared", limit: 5)
      end
    end
    20.times { ready.pop }
    20.times { go << true }
    expect(threads.map(&:value).count(true)).to be <= 5
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  it "fails closed on an unavailable or unsupported cache" do
    cache = AddAuth.configuration.rate_limit_store
    allow(cache).to receive(:increment).and_return(nil)
    expect { runtime.limit(key: "account", limit: 5) }.to raise_error(AddAuth::Error, /unavailable/)
    allow(cache).to receive(:increment).and_raise(IOError)
    expect { runtime.limit(key: "account", limit: 5) }.to raise_error(AddAuth::Error, /unavailable/)
  end
end
