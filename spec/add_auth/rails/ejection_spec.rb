# frozen_string_literal: true

require "rails_helper"
require "tmpdir"
require "open3"
require "add_auth/rails/ejection"

RSpec.describe AddAuth::Rails::Ejection do
  around do |example|
    Dir.mktmpdir("add_auth-ejection") do |root|
      @host, @engine = File.join(root, "host"), File.join(root, "engine")
      FileUtils.mkdir_p(File.join(@engine, "app/views/add_auth/sign_ins"))
      @source = "app/views/add_auth/sign_ins/_form.html.erb"
      File.write(File.join(@engine, @source), "original upstream\n")
      example.run
    end
  end

  subject(:ejection) { described_class.new(host_root: @host, engine_root: @engine) }

  it "preserves host changes and original fingerprints while reporting an applicable upstream diff" do
    ejection.install(kind: :views, only: "email_link")
    expect(ejection.report.first).to include(customized: false, upstream_changed: false)
    File.write(File.join(@host, @source), "host-private-customization\n")
    File.write(File.join(@engine, @source), "new upstream\n")
    ejection.install(kind: :views, only: "email_link")
    report = ejection.report.first
    expect(report).to include(customized: true, upstream_changed: true)
    expect(report[:diff]).not_to include("host-private-customization")
    original = File.join(@host, "original")
    File.write(original, "original upstream\n")
    output, error, result = Open3.capture3("patch", original, stdin_data: report[:diff])
    expect(result.success?).to be(true), output + error
    expect(File.read(original)).to eq("new upstream\n")
    expect(File.read(File.join(@host, @source))).to eq("host-private-customization\n")
    FileUtils.rm(File.join(@host, @source))
    expect(ejection.report.first[:missing]).to be(true)
  end

  it "rejects forged sources and malformed manifest entries" do
    ejection.install(kind: :views, only: "email_link")
    path = File.join(@host, described_class::MANIFEST)
    manifest = JSON.parse(File.read(path))
    manifest["files"][@source]["source"] = "../../private"
    File.write(path, JSON.generate(manifest))
    expect { ejection.report }.to raise_error(AddAuth::Error, /manifest/)
    File.write(path, JSON.generate(files: {@source => false}))
    expect { ejection.report }.to raise_error(AddAuth::Error, /manifest/)
  end
end
