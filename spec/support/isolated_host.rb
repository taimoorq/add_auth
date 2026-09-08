# frozen_string_literal: true

require "open3"
require "tmpdir"
require "fileutils"
require "rubygems/package"
require "rubygems/installer"

# A separate process, bundle and database for package/operations acceptance.
# Never boots or changes the shared spec/dummy fixture.
class IsolatedHost
  attr_reader :root, :directory, :environment

  def initialize(directory)
    @directory = directory
    @root = File.join(directory, "host")
    @environment = {"RAILS_ENV" => "test", "DATABASE_URL" => nil, "RAILS_MASTER_KEY" => nil,
                    "SECRET_KEY_BASE" => "isolated-host-test-secret-" * 4, "ADD_AUTH_TEST_DATABASE_URL" => nil}
    execute(Gem.bin_path("railties", "rails"), "new", root, "--skip-test", "--skip-asset-pipeline",
      "--skip-bundle", "--skip-git", "--skip-hotwire", "--skip-javascript", "--skip-jbuilder", "--skip-bootsnap")
    bundle = File.join(root, "Gemfile")
    @environment.merge!("BUNDLE_GEMFILE" => bundle, "BUNDLER_ORIG_BUNDLE_GEMFILE" => bundle,
      "BUNDLE_LOCKFILE" => "#{bundle}.lock", "BUNDLER_ORIG_BUNDLE_LOCKFILE" => "#{bundle}.lock")
  end

  def install(artifact, label:, extra_gems: [])
    installed = Gem::Installer.at(artifact, install_dir: File.join(directory, label),
      ignore_dependencies: true, wrappers: false).install
    File.write(File.join(installed.full_gem_path, "add_auth.gemspec"), installed.to_ruby)
    File.write(File.join(root, "Gemfile"), <<~RUBY)
      source "https://rubygems.org"
      gem "add_auth", path: #{installed.full_gem_path.inspect}
      gem "rails", "=#{Gem.loaded_specs.fetch("railties").version}"
      gem "sqlite3", ">= 2.1"
      gem "puma"
      #{extra_gems.map { |name| "gem #{name.inspect}" }.join("\n")}
    RUBY
    execute(Gem.bin_path("bundler", "bundle"), "install", "--local", chdir: root)
    installed.full_gem_path
  end

  def run(*arguments)
    execute("bin/rails", *arguments, chdir: root)
  end

  def runner(source, variables = {})
    file = File.join(directory, "runner-#{SecureRandom.hex(6)}.rb")
    File.write(file, source, mode: "w", perm: 0o600)
    execute("bin/rails", "runner", file, chdir: root, variables: variables)
  end

  def configure
    File.open(File.join(root, "config/initializers/add_auth.rb"), "a") do |file|
      file.puts <<~RUBY

        AddAuth.configure do |config|
          config.base_url = "https://example.test"
          config.mail_from = "sign-in@example.test"
          config.rate_limit_store = ActiveSupport::Cache::MemoryStore.new
          config.passkeys.rp_id = "example.test"
          config.passkeys.origins = ["https://example.test"]
          config.trusted_recovery_address = ->(user) { user.email_address }
          config.support_url = "/support"
        end
        ActiveJob::Base.queue_adapter = :test
        ActionMailer::Base.delivery_method = :test
      RUBY
    end
  end

  def self.candidate(directory)
    specification = Gem::Specification.load(File.expand_path("../../add_auth.gemspec", __dir__))
    artifact = File.join(directory, "candidate.gem")
    Gem::Package.build(specification, false, false, artifact)
    artifact
  end

  def spawn(*arguments, variables: {}, log: "worker.log")
    Process.spawn(environment.merge(variables), RbConfig.ruby, *arguments,
      chdir: root, out: File.join(directory, log), err: [:child, :out])
  end

  private

  def execute(*arguments, chdir: directory, variables: {})
    output, error, result = Open3.capture3(environment.merge(variables), RbConfig.ruby, *arguments, chdir: chdir)
    raise "Isolated host #{arguments.first(2).join(" ")} failed:\n#{output}\n#{error}" unless result.success?
    output
  end
end
