# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require_relative "../support/devise_source_host"

RSpec.describe "Synchronized Devise source writes" do
  it "preserves current source passwords across stale objects and refuses writes after authority changes" do
    Dir.mktmpdir("add-auth-source-bridge-") do |directory|
      profile = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? :uuid : :standard
      host = DeviseSourceHost.new(directory)
      host.prepare(profile: profile)
      host.prepare_accounts
      output = host.runner(<<~RUBY)
        require "add_auth/rails/migration/source_bridge"
        User.include AddAuth::Rails::Migration::SourceBridge
        user = User.find_by!(email: "source-0@example.test")
        stale = User.find(user.id)
        user.update!(password: "source-changed-password")
        stale.update!(sign_in_count: 1)
        user.reload
        abort "stale source copy replaced current password" unless user[:password_digest] == user.encrypted_password && user.valid_password?("source-changed-password")
        abort "old source password survived" if user.valid_password?("source-password")
        user.increment_failed_attempts
        abort "active source counter write was rejected" unless user.reload.failed_attempts == 1
        stale_attempts = User.find(user.id)
        stale = User.find(user.id)
        user.update_columns(add_auth_authority: "add_auth")
        begin
          stale.update!(password: "old-worker-write")
          abort "stale worker overwrote destination authority"
        rescue AddAuth::Error
        end
        user.reload
        abort "source password path remained reachable" if user.valid_password?("source-changed-password") || user.active_for_authentication?
        abort "destination password was overwritten" unless user[:password_digest] == user.encrypted_password
        abort "bridge sent mail" unless ActionMailer::Base.deliveries.empty?
        before_attempts = user.reload.failed_attempts
        begin
          stale_attempts.valid_for_authentication? { false }
          abort "retired failed-attempt writer remained reachable"
        rescue AddAuth::Error
        end
        abort "retired bulk counter write committed" unless user.reload.failed_attempts == before_attempts

        # Ordinary profile/tracking writes remain safe after retirement.
        user.update!(sign_in_count: 2)
        abort "retired profile write was rejected" unless user.reload.sign_in_count == 2

        unconfirmed = User.find_by!(email: "source-1@example.test")
        raw_confirm, confirm_digest = Devise.token_generator.generate(User, :confirmation_token)
        unconfirmed.update_columns(confirmation_token: confirm_digest, confirmation_sent_at: Time.current)
        stale_confirmation = User.find(unconfirmed.id)
        unconfirmed.update_columns(add_auth_authority: "add_auth")
        begin
          User.confirm_by_token(raw_confirm)
          abort "retired confirmation token changed destination state"
        rescue AddAuth::Error
        end
        begin
          stale_confirmation.confirm
          abort "stale source confirmation changed destination state"
        rescue AddAuth::Error
        end
        abort "late confirmation was committed" if unconfirmed.reload.confirmed_at

        locked = User.find_by!(email: "source-2@example.test")
        raw_unlock, unlock_digest = Devise.token_generator.generate(User, :unlock_token)
        locked.update_columns(unlock_token: unlock_digest, failed_attempts: 7)
        stale_lock = User.find(locked.id)
        locked.update_columns(add_auth_authority: "add_auth")
        before_lock = locked.reload.locked_at
        begin
          User.unlock_access_by_token(raw_unlock)
          abort "retired unlock token cleared destination lock"
        rescue AddAuth::Error
        end
        begin
          stale_lock.update!(locked_at: nil, failed_attempts: 0)
          abort "stale source save cleared destination lock"
        rescue AddAuth::Error
        end
        abort "late unlock was committed" unless locked.reload.locked_at == before_lock && locked.failed_attempts == 7

        raw_reset, reset_digest = Devise.token_generator.generate(User, :reset_password_token)
        user.update_columns(reset_password_token: reset_digest, reset_password_sent_at: Time.current)
        old_digest = user.encrypted_password
        begin
          User.reset_password_by_token(reset_password_token: raw_reset, password: "retired-reset-password", password_confirmation: "retired-reset-password")
          abort "retired reset token changed destination password"
        rescue AddAuth::Error
        end
        abort "late reset was committed" unless user.reload.encrypted_password == old_digest && user[:password_digest] == old_digest
        puts "stale-source/authority/password bridge verified"
        puts "retired confirmation/unlock/reset/stale-lock fences verified"
      RUBY
      expect(output).to include("stale-source/authority/password bridge verified", "retired confirmation/unlock/reset/stale-lock fences verified")
    ensure
      host&.cleanup
    end
  end
end
