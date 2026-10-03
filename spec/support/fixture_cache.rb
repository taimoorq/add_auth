# frozen_string_literal: true

require "digest"
require "tmpdir"
require_relative "test_reporting"

# Derived, immutable setup only. Each acceptance host still owns its app and DB.
module AddAuthFixtureCache
  module_function

  def root
    return File.expand_path(ENV.fetch("ADD_AUTH_FIXTURE_CACHE")) if ENV["ADD_AUTH_FIXTURE_CACHE"]
    @temporary_root ||= begin
      path = Dir.mktmpdir("add-auth-fixture-cache-")
      at_exit { FileUtils.remove_entry(path) if File.directory?(path) }
      path
    end
  end

  def fingerprint(parts)
    digest = Digest::SHA256.new
    parts.each do |name, content|
      digest << name.bytesize.to_s << ":" << name << content.bytesize.to_s << ":" << content
    end
    digest.hexdigest
  end

  def files(directory)
    Dir.chdir(directory) do
      Dir.glob("**/*", File::FNM_DOTMATCH).select { |path| File.file?(path) && path != ".complete.json" }.sort.to_h do |path|
        [path, Digest::SHA256.file(path).hexdigest]
      end
    end
  end

  def fetch(namespace:, key:)
    raise ArgumentError, "invalid fixture cache identity" unless /\A[a-z-]+\z/.match?(namespace) && /\A[0-9a-f]{64}\z/.match?(key)
    parent = File.join(root, namespace)
    FileUtils.mkdir_p(parent)
    path = File.join(parent, key)
    File.open("#{path}.lock", "w") do |lock|
      lock.flock(File::LOCK_EX)
      receipt_path = File.join(path, ".complete.json")
      receipt = JSON.parse(File.read(receipt_path)) if File.file?(receipt_path)
      if receipt && receipt["key"] == key && receipt["files"] == files(path)
        return AddAuthTestReporting.measure("cache_hit:#{namespace}") { path }
      end
      FileUtils.rm_rf(path)
      FileUtils.mkdir_p(path)
      AddAuthTestReporting.measure("cache_build:#{namespace}") { yield path }
      File.write(receipt_path, JSON.generate(key: key, files: files(path)))
      path
    rescue
      FileUtils.rm_rf(path)
      raise
    end
  end
end
