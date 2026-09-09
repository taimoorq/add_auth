# frozen_string_literal: true

require "spec_helper"
require "tmpdir"
require "fileutils"
require "json"
require "open3"
require "add_auth/migration/static_inventory"

RSpec.describe AddAuth::Migration::StaticInventory do
  around do |example|
    Dir.mktmpdir("add-auth-preflight-") do |root|
      @root = root
      FileUtils.mkdir_p(File.join(root, "app/models"))
      File.write(File.join(root, "Gemfile.lock"), "GEM\n  specs:\n    devise (5.0.4)\n    rails (8.1.3.1)\n")
      example.run
    end
  end

  def write(path, source)
    FileUtils.mkdir_p(File.dirname(File.join(@root, path)))
    File.write(File.join(@root, path), source)
  end

  def report = described_class.new(root: @root).call

  it "inventories real Ruby syntax without evaluating code or echoing literals" do
    write("app/models/user.rb", <<~RUBY)
      raise "MUST NOT EXECUTE"
      class User < ApplicationRecord
        devise :database_authenticatable,
          :confirmable, pepper: "DO-NOT-PRINT-secret"
        # warden should not count in a comment
      end
    RUBY
    result = report
    expect(result.dig(:facts, :modules)).to eq(%w[confirmable database_authenticatable])
    expect(result.dig(:facts, :scope_count)).to eq(1)
    expect(result.dig(:facts, :surfaces, :warden)).to be_empty
    expect(JSON.generate(result)).not_to include("DO-NOT-PRINT", "MUST NOT EXECUTE")
    expect(result[:migration_ready]).to be(false)
  end

  it "recognizes parenthesized declarations and refuses dynamic or unknown modules" do
    write("app/models/user.rb", "class User; devise(:database_authenticatable, *configured_modules); end")
    expect(report.dig(:facts, :complete)).to be(false)
    write("app/models/user.rb", "class User; devise(:database_authenticatable, :two_factor_authenticatable); end")
    expect(report.dig(:facts, :unknown_modules)).to eq(1)
    expect(report[:blockers].map { |entry| entry[:code] }).to include("unsupported_extension")
  end

  it "finds Rack Warden lookups and quoted credential columns without exposing literal values" do
    write("config/initializers/admin.rb", 'current_user = request.env["warden"].user')
    write("app/models/user.rb", 'scope :prepared, -> { where("password_digest" => "private-hash-value") }')
    expect(report.dig(:facts, :surfaces, :warden)).to eq(["config/initializers/admin.rb"])
    expect(report.dig(:facts, :surfaces, :passwords)).to eq(["app/models/user.rb"])
    expect(JSON.generate(report)).not_to include("private-hash-value")
  end

  it "caps total content across individually bounded files" do
    stub_const("AddAuth::Migration::StaticInventory::TOTAL_BYTES", 50)
    3.times { |index| write("app/models/user_#{index}.rb", "#" + "x" * 24) }
    expect(report.dig(:facts, :complete)).to be(false)
    expect(report.dig(:facts, :files_inspected)).to eq(2)
  end

  it "reports multiple scopes, extensions and customized target files" do
    write("app/models/user.rb", "class User; devise :database_authenticatable; end")
    write("app/models/admin.rb", "class Admin; devise :database_authenticatable; end")
    File.open(File.join(@root, "Gemfile.lock"), "a") { |file| file.puts "    devise-jwt (0.12.1)" }
    expect(report.dig(:facts, :scope_count)).to eq(2)
    expect(report.dig(:facts, :extensions)).to eq(["devise-jwt"])
    expect(report.dig(:facts, :target_conflicts)).to include("app/models/user.rb")
  end

  it "does not follow file or directory symlinks or inspect credentials" do
    Dir.mktmpdir do |outside|
      File.write(File.join(outside, "user.rb"), "class User; devise :lockable; end")
      File.symlink(File.join(outside, "user.rb"), File.join(@root, "app/models/user.rb"))
      File.symlink(outside, File.join(@root, "app/models/elsewhere"))
      write("config/credentials.rb", "raise 'secret'")
      expect(report.dig(:facts, :complete)).to be(false)
      expect(report.dig(:facts, :modules)).to be_empty
      expect(report.dig(:facts, :files_inspected)).to eq(0)
    end
  end

  it "bounds input and reports parse failures without source disclosure" do
    write("app/models/user.rb", "x" * (described_class::MAX_BYTES + 1))
    expect(report.dig(:facts, :complete)).to be(false)
    write("app/models/user.rb", "class User <")
    expect(report.dig(:facts, :complete)).to be(false)
  end

  it "runs the packaged command without loading a host Gemfile or Rails" do
    write("Gemfile", "abort 'Gemfile executed'")
    write("config/application.rb", "abort 'application executed'")
    output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "exe/add_auth-preflight", "--root", @root)
    expect(status.success?).to be(true), error
    expect(JSON.parse(output).fetch("status")).to eq("inventory")
    expect(output).not_to include("executed")
  end
end
