# frozen_string_literal: true

# Explicit acceptance command: baseline archive is fetched outside the test,
# then checked against the independently verified registry checksum.
require "rails"
require "rails/generators"
require "digest"
require_relative "../support/isolated_host"

RSpec.describe "Upgrade from the published AddAuth package" do
  it "preserves persisted authority, pending delivery and host files across upgrade and rollback" do
    baseline = File.expand_path(ENV.fetch("ADD_AUTH_BASELINE_GEM"))
    expect(Digest::SHA256.file(baseline).hexdigest).to eq("7c3dc3d95e85d74887d1a607f47d85d702e52e5b6771aac9fa8002f046581725")
    Dir.mktmpdir("add-auth-upgrade-") do |directory|
      host = IsolatedHost.new(directory)
      host.install(baseline, label: "baseline")
      host.run("generate", "authentication")
      host.run("generate", "add_auth:passkeys")
      host.configure
      host.run("db:prepare")
      %w[views controllers javascript mailer_views].each { |kind| host.run("generate", "add_auth:#{kind}") }
      view = "app/views/add_auth/sign_ins/_form.html.erb"
      File.open(File.join(host.root, view), "a") { |file| file.puts "<p>Host customization survives</p>" }
      original = File.binread(File.join(host.root, view))
      manifest_path = File.join(host.root, "config/add_auth-ejections.json")
      manifest = File.binread(manifest_path)
      journey = File.read(File.expand_path("../support/upgrade_journey.rb", __dir__))
      expect(host.runner(journey, "ADD_AUTH_UPGRADE_PHASE" => "seed")).to include("upgrade state seeded")

      candidate = host.install(IsolatedHost.candidate(directory), label: "candidate")
      2.times do
        host.run("generate", "add_auth:passkeys")
        host.run("db:migrate")
      end
      expect(File.binread(manifest_path)).to eq(manifest)
      expect(File.binread(File.join(host.root, view))).to eq(original)
      expect(host.runner(journey, "ADD_AUTH_UPGRADE_PHASE" => "verify")).to include("upgrade authority verified")
      # Delivery executes in a fresh worker process, outside the HTTP executor.
      expect(host.runner(<<~RUBY)).to include("baseline notification delivered")
        notification = AddAuthSecurityEvent.where(delivered_at: nil, revoked_at: nil).first
        abort "baseline notification missing" unless notification
        AddAuth::SecurityNotificationJob.perform_now(notification.id)
        abort "baseline notification lost" unless notification.reload.delivered_at
        puts "baseline notification delivered"
      RUBY

      # Deliberately synthetic upstream edit: prove a real populated host can
      # review and accept a changed baseline without overwriting its own view.
      File.open(File.join(candidate, view), "a") { |file| file.puts "<%# synthetic upstream upgrade fixture %>" }
      expect(host.runner(<<~RUBY)).to include("reviewed ejection verified")
        require "add_auth/rails/doctor"
        doctor = AddAuth::Rails::Doctor.new
        abort "unreported upstream change" unless doctor.call.any? { |problem| problem.include?("ejection") }
        entry = doctor.ejections.find { |item| item[:path] == #{view.inspect} }
        abort "missing upstream diff" unless entry && entry[:diff].include?("synthetic upstream upgrade fixture")
        abort "private host source in upstream diff" if entry[:diff].include?("Host customization survives")
        puts "reviewed ejection verified"
      RUBY
      baseline_data = JSON.parse(File.read(manifest_path))
      baseline_data.fetch("files").delete(view)
      File.write(manifest_path, JSON.generate(baseline_data))
      host.run("generate", "add_auth:views")
      expect(File.binread(File.join(host.root, view))).to eq(original)
      expect(host.run("add_auth:doctor")).to include("configuration checks passed")

      # Reinstall the exact previous package with its original ejection baseline.
      # Revoked sessions and spent proofs must stay rejected after code rollback.
      File.binwrite(manifest_path, manifest)
      host.install(baseline, label: "rollback")
      expect(host.runner(journey, "ADD_AUTH_UPGRADE_PHASE" => "rollback")).to include("rollback authority verified")
      expect(host.run("add_auth:doctor")).to include("configuration checks passed")
    end
  end
end
