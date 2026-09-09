# frozen_string_literal: true

# Contributor rehearsal recipe, not a deployment command or stable gem API.
# Run under an isolated Rails test host. Review the manifest before each run.
require "json"
require "digest"
require "securerandom"
require "add_auth/core/migration/account_adoption"
require "add_auth/rails/migration/account_store"

module DeviseBackfillRehearsal
  REQUIRED = %w[owner environment database source_revision config_revision recovery_snapshot rollback_artifact expected_accounts].freeze

  def self.batch(manifest:, checkpoint:, source_revision:, config_revision:, limit: 100, after_commit: -> {})
    unless manifest.keys.sort == REQUIRED.sort && manifest.values.all? { |value| value.to_s.size.between?(1, 256) } &&
        manifest["expected_accounts"].is_a?(Integer) && manifest["expected_accounts"] >= 0 &&
        Rails.env.test? && manifest["environment"] == "test" &&
        manifest["database"] == User.connection_db_config.database &&
        manifest["source_revision"] == source_revision && manifest["config_revision"] == config_revision
      raise ArgumentError, "rehearsal manifest does not match this source, configuration and test database"
    end
    identity = Digest::SHA256.hexdigest(JSON.generate(manifest.sort.to_h))
    path = File.expand_path(checkpoint)
    raise ArgumentError, "checkpoint parent must be a private directory" unless (File.stat(File.dirname(path)).mode & 0o077).zero?
    flags = File::RDWR | File::CREAT | File::NOFOLLOW
    File.open(path + ".lock", flags, 0o600) do |lock|
      raise ArgumentError, "another backfill owns this checkpoint" unless lock.flock(File::LOCK_EX | File::LOCK_NB)
      state = if File.exist?(path) || File.symlink?(path)
        File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
          raise ArgumentError, "checkpoint is not private or is oversized" unless (file.stat.mode & 0o077).zero? && file.stat.size <= 4096
          JSON.parse(file.read)
        end
      else
        {"manifest" => identity, "cursor" => nil, "complete" => false}
      end
      raise ArgumentError, "checkpoint belongs to another manifest" unless state["manifest"] == identity
      raise ArgumentError, "account counts changed; reconcile the manifest" unless User.unscoped.count == manifest["expected_accounts"]
      return state if state.fetch("complete")

      conversion = AddAuth::Core::Migration::AccountAdoption.new(store: AddAuth::Rails::Migration::AccountStore.new(user_model: User))
      result = conversion.call(after: state.fetch("cursor"), limit: limit)
      # No checkpoint advancement on ambiguity. Repeat from the previous cursor
      # after protected operator reconciliation; Core never merges accounts.
      raise ArgumentError, "batch needs reconciliation; checkpoint retained" if result.values_at(:conflicts, :changed_source, :active_destination).any?(&:positive?)
      after_commit.call # Fault injection in the contributor acceptance fixture.
      state = {"manifest" => identity, "cursor" => result[:next_cursor], "complete" => result[:next_cursor].nil?, "last_batch" => result}
      temporary = path + ".#{SecureRandom.hex(12)}"
      begin
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
          file.write(JSON.generate(state))
          file.flush
          file.fsync
        end
        File.rename(temporary, path)
        File.open(File.dirname(path)) { |directory| directory.fsync }
      ensure
        File.unlink(temporary) if File.exist?(temporary)
      end
      state
    end
  end
end
