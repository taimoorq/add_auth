# frozen_string_literal: true

# Explicit acceptance command: baseline archive is fetched outside the test,
# then checked against the independently verified registry checksum.
require "rails"
require "rails/generators"
require "digest"
require "rubygems/package"
require_relative "../support/isolated_host"

RSpec.describe "Upgrade from the published AddAuth package" do
  it "preserves persisted authority, pending delivery and host files across upgrade and rollback" do
    baseline = File.expand_path(ENV.fetch("ADD_AUTH_BASELINE_GEM"))
    published = {
      "7c3dc3d95e85d74887d1a607f47d85d702e52e5b6771aac9fa8002f046581725" => "0.2.1",
      "c66189b571c2acc47ef9574c045359956a97bf734692f28d29749aef8b2c8673" => "0.2.2"
    }
    checksum = Digest::SHA256.file(baseline).hexdigest
    expect(published).to have_key(checksum)
    expect(Gem::Package.new(baseline).spec.version.to_s).to eq(published.fetch(checksum))
    puts "Verified published baseline #{published.fetch(checksum)}"
    Dir.mktmpdir("add-auth-upgrade-") do |directory|
      host = IsolatedHost.new(directory)
      # Match the generated Rails test configuration on CI locally too. Lazy
      # loading can hide candidate-only ejections left behind during rollback.
      host.environment["CI"] = "true"
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
      original_ejections = JSON.parse(manifest).fetch("files").keys.to_h do |path|
        [path, File.binread(File.join(host.root, path))]
      end
      journey = File.read(File.expand_path("../support/upgrade_journey.rb", __dir__))
      expect(host.runner(journey, {"ADD_AUTH_UPGRADE_PHASE" => "seed"})).to include("upgrade state seeded")

      candidate = host.install(IsolatedHost.candidate(directory), label: "candidate")
      2.times do
        host.run("generate", "add_auth:passkeys")
        host.run("db:migrate")
      end
      expect(File.binread(manifest_path)).to eq(manifest)
      expect(File.binread(File.join(host.root, view))).to eq(original)
      expect(host.runner(journey, {"ADD_AUTH_UPGRADE_PHASE" => "verify"})).to include("upgrade authority verified")
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
      # This fixture reviews every actual upstream change, not just its
      # synthetic one. Regenerate pristine copies and explicitly merge the
      # known host customization; normal generator reruns must never do this.
      baseline_data = JSON.parse(File.read(manifest_path))
      baseline_data.fetch("files").dup.each do |path, entry|
        upstream = File.read(File.join(candidate, entry.fetch("source")))
        next if Digest::SHA256.hexdigest(upstream) == entry.fetch("source_hash")
        if path == view
          File.write(File.join(host.root, path), upstream + "\n<p>Host customization survives</p>\n")
        else
          expect(Digest::SHA256.file(File.join(host.root, path)).hexdigest).to eq(entry.fetch("generated_hash"))
          FileUtils.rm(File.join(host.root, path))
        end
        baseline_data.fetch("files").delete(path)
      end
      File.write(manifest_path, JSON.generate(baseline_data))
      %w[views controllers javascript mailer_views].each { |kind| host.run("generate", "add_auth:#{kind}") }
      expect(File.binread(File.join(host.root, view))).to include("Host customization survives", "synthetic upstream upgrade fixture")
      expect(host.run("add_auth:doctor")).to include("configuration checks passed")
      expect(host.runner(<<~RUBY)).to include("merged host view rendered")
        client = ActionDispatch::Integration::Session.new(Rails.application)
        client.get "/sign-in"
        abort "merged view did not render" unless client.response.status == 200 && client.response.body.include?("Host customization survives")
        puts "merged host view rendered"
      RUBY

      # Restore the complete previous presentation, including its file set.
      # Candidate-only controllers can require APIs absent from the old gem even
      # when their optional routes are disabled. Never silently remove an edited
      # host file: this fixture only discards pristine, manifest-owned ejections.
      candidate_ejections = JSON.parse(File.read(manifest_path)).fetch("files")
      (candidate_ejections.keys - original_ejections.keys).each do |path|
        file = File.join(host.root, path)
        expect(Digest::SHA256.file(file).hexdigest).to eq(candidate_ejections.fetch(path).fetch("generated_hash"))
        FileUtils.rm(file)
      end
      # Reinstall the exact previous package with its original ejection baseline.
      # Revoked sessions and spent proofs must stay rejected after code rollback.
      File.binwrite(manifest_path, manifest)
      original_ejections.each { |path, contents| File.binwrite(File.join(host.root, path), contents) }
      host.install(baseline, label: "rollback")
      expect(host.runner(journey, {"ADD_AUTH_UPGRADE_PHASE" => "rollback"})).to include("rollback authority verified")
      expect(host.run("add_auth:doctor")).to include("configuration checks passed")
    end
  end
end
