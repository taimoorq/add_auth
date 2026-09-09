# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require_relative "../support/devise_source_host"

RSpec.describe "Rollback to a canonical-reader compatibility build" do
  profiles = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? [:uuid] : %i[standard aligned]
  profiles.each do |profile|
    it "retains current #{profile} credentials and revocations across a fresh compatibility process" do
      Dir.mktmpdir("add-auth-compatible-rollback-") do |directory|
        host = DeviseSourceHost.new(directory)
        host.prepare(profile: profile)
        host.prepare_accounts
        host.password_destination(profile: profile)
        %w[accounts external_identities mobile_sessions].each { |feature| host.run("generate", "add_auth:#{feature}") }
        host.run("db:migrate")
        File.open(File.join(host.root, "config/initializers/add_auth.rb"), "a") do |file|
          file.puts <<~RUBY
            AddAuth.configure do |config|
              config.lifecycle.enabled = true
              config.eligible = ->(_user) { true }
              config.mobile.enabled = true
              config.mobile.clients = ["fixture"]
              config.mobile.lifetime = 30 * 86400
              config.mobile.idle_timeout = 14 * 86400
              config.external_identities.register(id: "fixture", label: "Fixture", middleware_name: "fixture",
                configuration: AddAuth::Core::ExternalIdentities::Configuration.new(id: "fixture", issuer: "https://identity.example.test",
                  audience: "fixture", verifier: ->(**) { nil }))
              config.external_identities.enabled = true
            end
          RUBY
        end
        receipt = File.join(directory, "private-authority.json")
        host.runner(<<~RUBY)
          require "json"
          runtime = AddAuth::Rails::Runtime
          user = User.find_by!(email_address: "source-0@example.test")
          original_id = user.id
          browser = runtime.sessions.start(user: user, method: :password)
          mobile = runtime.sessions.start(user: user, method: :password, transport: :mobile, client_id: "fixture")
          runtime.accounts.issue(identifier: user.email_address, purpose: :reset_password)
          row = AddAuthAccountToken.where(user_id: user.id, purpose: "reset_password").last
          reset = runtime.accounts.claim_delivery(digest: row.digest).fetch(:token)
          abort "reset failed" unless runtime.accounts.consume(token: reset, purpose: :reset_password, password: "current-rollback-password").success?
          def elevation(user, purpose)
            runtime = AddAuth::Rails::Runtime
            AddAuth.configuration.rate_limit_store.clear
            session = runtime.sessions.start(user: user.reload, method: :password).session
            result = runtime.elevate_password(user: user, session: session, purpose: purpose, password: "current-rollback-password", ip: "127.0.0.1", challenge_token: nil)
            abort "fixture elevation failed" unless result.success?
            result.session
          end
          session = elevation(user, :change_email)
          abort "address change failed" unless runtime.accounts.change_email(user: user, session: session, identifier: "current-address@example.test").success?
          row = AddAuthAccountToken.where(user_id: user.id, purpose: "confirm").last
          confirmation = runtime.accounts.claim_delivery(digest: row.digest).fetch(:token)
          abort "address confirmation failed" unless runtime.accounts.consume(token: confirmation, purpose: :confirm).success?
          configuration = AddAuth.configuration.external_identities.configurations.first
          binding = AddAuthExternalIdentity.create!(user: user, namespace: configuration.namespace("retired-subject"), provider_id: configuration.id,
            issuer: configuration.issuer, audience: configuration.audience, subject: "retired-subject", provenance: "synthetic-import",
            credential_version: SecureRandom.uuid, linked_at: Time.current)
          session = elevation(user, :unlink_external_identity)
          proof = runtime.sessions.with_elevation(user: user, session: session, purpose: :unlink_external_identity, policy: runtime.step_up_policy)
          abort "unlink failed" unless runtime.external_identities.unlink(user: user, session: session, identity_id: binding.id, grant: proof.credential).success?
          deleted = User.create!(email_address: "deleted@example.test", password: "current-rollback-password", confirmed_at: Time.current, add_auth_authority: "add_auth")
          deleted_id = deleted.id
          deleted_session = elevation(deleted, :delete_account)
          abort "deletion failed" unless runtime.accounts.delete_account(user: deleted, session: deleted_session).success?
          File.write(#{receipt.inspect}, JSON.generate({id: original_id, deleted_id: deleted_id, binding_id: binding.id,
            browser: browser.bearer, mobile: mobile.bearer, reset: reset, confirmation: confirmation}), mode: "w", perm: 0o600)
        RUBY

        # This bridge contains the same reviewed canonical authentication code.
        # The legacy model exists only to exercise retired worker calls. It is
        # never mounted as a second sign-in or session reader.
        host.install(DeviseSourceHost.candidate(directory), label: "compatible-bridge", extra_gems: ["devise", "pg"])
        File.write(File.join(host.root, "app/models/legacy_user.rb"), <<~RUBY)
          require "devise/orm/active_record"
          require "add_auth/rails/migration/source_bridge"
          class LegacyUser < ApplicationRecord
            self.table_name = "users"
            devise :database_authenticatable, :recoverable, :confirmable, :lockable
            include AddAuth::Rails::Migration::SourceBridge
          end
        RUBY
        output = host.runner(<<~RUBY)
          require "json"
          state = JSON.parse(File.read(#{receipt.inspect}))
          runtime = AddAuth::Rails::Runtime
          user = User.find(state.fetch("id"))
          abort "current address lost" unless user.email_address == "current-address@example.test" && user.confirmed_at
          abort "current password lost" unless user.authenticate("current-rollback-password")
          abort "old password resurrected" if user.authenticate("source-password")
          abort "old browser resurrected" if runtime.sessions.resume(signed_value: state.fetch("browser"))
          abort "old mobile resurrected" if runtime.sessions.resume_mobile(bearer: state.fetch("mobile"))
          abort "spent reset resurrected" if runtime.accounts.consume(token: state.fetch("reset"), purpose: :reset_password, password: "resurrected-password").success?
          abort "spent confirmation resurrected" if runtime.accounts.consume(token: state.fetch("confirmation"), purpose: :confirm).success?
          abort "provider binding resurrected" unless AddAuthExternalIdentity.find(state.fetch("binding_id")).revoked_at
          abort "deleted account resurrected" if User.exists?(state.fetch("deleted_id"))
          legacy = LegacyUser.find(user.id)
          abort "Devise reader became authoritative" if legacy.valid_password?("source-password") || legacy.active_for_authentication?
          begin
            legacy.update!(password: "stale-worker-password")
            abort "stale worker overwrote current password"
          rescue AddAuth::Error
          end
          abort "worker changed canonical password" unless user.reload.authenticate("current-rollback-password")
          client = ActionDispatch::Integration::Session.new(Rails.application)
          client.post "/sign-in/password", params: {email_address: user.email_address, password: "current-rollback-password"}
          abort "canonical reader unavailable after rollback" unless client.response.status == 303
          client.get "/users/sign_in"
          abort "unreviewed Devise route mounted" unless client.response.status == 404
          puts "fresh compatibility boot/current password/address/proof/mobile/unlink/deletion fences verified"
        RUBY
        expect(output).to include("fresh compatibility boot/current password/address/proof/mobile/unlink/deletion fences verified")
      ensure
        host&.cleanup
      end
    end
  end
end
