# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require_relative "../support/devise_source_host"

RSpec.describe "Account lifecycle in the adopted Rails host" do
  it "registers, confirms, resets and revokes through real transactions and encrypted proof delivery" do
    Dir.mktmpdir("add-auth-lifecycle-") do |directory|
      profile = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? :uuid : :standard
      host = DeviseSourceHost.new(directory)
      host.prepare(profile: profile)
      host.prepare_accounts
      host.password_destination(profile: profile)
      File.write(File.join(host.root, "app/controllers/verified_accounts_controller.rb"), <<~RUBY)
        class VerifiedAccountsController < ApplicationController
          def index = render html: "<h1>Signed in</h1>".html_safe, layout: false
        end
      RUBY
      routes = File.join(host.root, "config/routes.rb")
      File.write(routes, File.read(routes).sub("Rails.application.routes.draw do", "Rails.application.routes.draw do" + "\n  root to: 'verified_accounts#index'"))
      host.run("generate", "add_auth:accounts")
      host.run("db:migrate")
      File.open(File.join(host.root, "config/initializers/add_auth.rb"), "a") do |file|
        file.puts <<~RUBY
          AddAuth.configuration.lifecycle.enabled = true
          AddAuth.configuration.eligible = ->(_user) { true }
          AddAuth.configuration.lifecycle.provision = ->(user) { user.update_columns(sign_in_count: user.sign_in_count + 1) }
        RUBY
      end
      if ENV["ADD_AUTH_EJECT_UI"] == "1"
        host.runner(<<~RUBY)
          require "add_auth/rails/ejection"
          ejection = AddAuth::Rails::Ejection.new(host_root: Rails.root)
          %i[views controllers javascript mailer_views].each { |kind| ejection.install(kind: kind) }
        RUBY
      end
      output = host.runner(<<~RUBY)
        require "add_auth/rails/doctor"
        runtime = AddAuth::Rails::Runtime
        problems = AddAuth::Rails::Doctor.new.call
        abort "lifecycle doctor failed: \#{problems.join('; ')}" unless problems.empty?
        lifecycle = runtime.accounts
        email = "new-account@example.test"
        result = lifecycle.register(identifier: email, password: "new-account-password")
        abort "registration failed" unless result.success? && result.user.nil?
        user = User.find_by!(email_address: email)
        abort "unconfirmed user admitted" if runtime.sessions.start(user: user, method: :password)
        abort "registration provisioned too early" unless user.sign_in_count == 0
        proof = AddAuthAccountToken.find_by!(user_id: user.id, purpose: "confirm")
        delivery = lifecycle.claim_delivery(digest: proof.digest)
        abort "encrypted recipient incorrect" unless delivery[:recipient] == email
        token = delivery[:token]
        abort "raw proof was persisted" if proof.attributes.values.any? { |value| value.to_s.include?(token) }
        2.times { abort "preview failed" unless lifecycle.preview(token: token, purpose: :confirm).success? }
        abort "preview consumed proof" if proof.reload.consumed_at
        abort "wrong purpose accepted" if lifecycle.consume(token: token, purpose: :unlock).success?
        abort "confirmation failed" unless lifecycle.consume(token: token, purpose: :confirm).success?
        abort "confirmation created a session" if Session.where(user_id: user.id).exists?
        abort "host provisioning failed" unless user.reload.sign_in_count == 1
        abort "confirmation replay accepted" unless lifecycle.consume(token: token, purpose: :confirm).reason == :consumed_token
        abort "host provisioning repeated" unless user.reload.sign_in_count == 1
        grant = runtime.sessions.start(user: user, method: :password)
        abort "confirmed user denied" unless grant
        initial_count = User.count
        abort "duplicate registration leaked" unless lifecycle.register(identifier: email, password: "other-strong-password").success?
        abort "duplicate account created" unless User.count == initial_count
        lifecycle.issue(identifier: email, purpose: :reset_password)
        reset = AddAuthAccountToken.where(user_id: user.id, purpose: "reset_password").last
        delivery = lifecycle.claim_delivery(digest: reset.digest)
        abort "reset token unavailable" unless delivery
        abort "invalid new password accepted" if lifecycle.consume(token: delivery[:token], purpose: :reset_password, password: "short").success?
        abort "invalid attempt burned reset" if reset.reload.consumed_at
        abort "password reset failed" unless lifecycle.consume(token: delivery[:token], purpose: :reset_password, password: "replacement-account-password").success?
        abort "prior session survived reset" if runtime.sessions.resume(signed_value: grant.bearer)
        abort "old password survived reset" if user.reload.authenticate("new-account-password")
        abort "new password failed" unless user.authenticate("replacement-account-password")
        abort "reset replay accepted" if lifecycle.consume(token: delivery[:token], purpose: :reset_password, password: "another-account-password").success?
        User.validate do
          if password && password.include?(email_address.split("@").first)
            errors.add(:password, "cannot contain the account name")
          end
        end
        preserved = runtime.sessions.start(user: user, method: :password)
        lifecycle.issue(identifier: email, purpose: :reset_password)
        restricted = AddAuthAccountToken.where(user_id: user.id, purpose: "reset_password").last
        restricted_token = lifecycle.claim_delivery(digest: restricted.digest).fetch(:token)
        abort "host reset validator bypassed" if lifecycle.consume(token: restricted_token, purpose: :reset_password, password: "new-account-forbidden").success?
        abort "invalid host password burned proof" if restricted.reload.consumed_at
        abort "invalid host password revoked session" unless runtime.sessions.resume(signed_value: preserved.bearer)
        abort "invalid host password persisted" unless user.reload.authenticate("replacement-account-password")
        elevation = runtime.elevate_password(user: user, session: preserved.session, purpose: :change_password,
          password: "replacement-account-password", ip: "127.0.0.1", challenge_token: nil)
        abort "password change elevation failed" unless elevation.success?
        abort "host change validator bypassed" if lifecycle.change_password(user: user, session: elevation.session, password: "new-account-forbidden").success?
        abort "valid host password denied" unless lifecycle.change_password(user: user, session: elevation.session, password: "allowed-replacement-password").success?
        abort "host password change not persisted" unless user.reload.authenticate("allowed-replacement-password")
        abort "host password change did not revoke" if runtime.sessions.resume(signed_value: elevation.credential.bearer)
        begin
          user.update!(email_address: "bypassed-claims@example.test")
          abort "direct host email write bypassed address ownership"
        rescue AddAuth::Error
          abort "rejected host address write persisted" unless user.reload.email_address == email
        end
        lifecycle.issue(identifier: email, purpose: :reset_password)
        pending = AddAuthAccountToken.where(user_id: user.id, purpose: "reset_password").last
        user.update!(disabled_at: Time.current)
        abort "disabled account's proof remained deliverable" if lifecycle.claim_delivery(digest: pending.digest)
        abort "disabled account admitted" if runtime.sessions.start(user: user, method: :password)
        abort "unknown email response differs" unless lifecycle.issue(identifier: "absent@example.test", purpose: :reset_password).success?
        puts "registration/confirmation/reset/revocation verified"
      RUBY
      expect(output).to include("registration/confirmation/reset/revocation verified")
      request_output = host.runner(<<~RUBY)
        ActiveJob::Base.queue_adapter = :inline
        ActionMailer::Base.deliveries.clear
        client = ActionDispatch::Integration::Session.new(Rails.application)
        original = User.find_by!(email_address: "source-0@example.test")
        old_reset = original.password_reset_token
        client.get "/passwords/\#{old_reset}/edit"
        abort "stock reset URL remained active" unless client.response.status == 302 && client.response.location.end_with?("/account/requests/reset_password")
        client.patch "/passwords/\#{old_reset}", params: {password: "stock-bypass-password", password_confirmation: "stock-bypass-password"}
        abort "stock reset mutation remained active" unless client.response.status == 303 && !original.reload.authenticate("stock-bypass-password")
        client.get "/account/sign-up"
        abort "registration form missing" unless client.response.status == 200 && client.response.body.include?("Create account")
        abort "auth page cached" unless client.response.headers["Cache-Control"].include?("no-store") && client.response.body.include?("turbo-cache-control")
        client.post "/account/sign-up", params: {email_address: "browser@example.test", password: "short"}, headers: {"Accept" => "text/vnd.turbo-stream.html"}
        abort "Turbo validation contract failed" unless client.response.status == 422 && client.response.body.include?('target="add_auth-content"')
        client.post "/account/sign-up", params: {email_address: "browser@example.test", password: "browser-account-password"}
        abort "registration redirect failed" unless client.response.status == 303
        mail = ActionMailer::Base.deliveries.last
        abort "confirmation mail not delivered" unless mail && mail.to == ["browser@example.test"]
        link = URI.parse(mail.body.decoded.scan(%r{https://[^[:space:]<>]+}).first)
        token = URI.decode_www_form(link.query).to_h.fetch("token")
        record = AddAuthAccountToken.find_by!(digest: AddAuth.configuration.sign_in_token_digest.digest(token))
        abort "delivered payload retained" unless record.delivered_at && record.delivery_payload.nil?
        client.get link.request_uri
        abort "proof GET missing" unless client.response.status == 200 && client.response.body.include?("Confirm this email address") && !record.reload.consumed_at
        client.head link.request_uri
        abort "mail scanner consumed proof" if record.reload.consumed_at
        client.post link.path, params: {token: token}
        abort "confirmation POST failed" unless client.response.status == 303 && record.reload.consumed_at
        client.post "/account/requests/reset_password", params: {email_address: "browser@example.test"}
        abort "reset mail intake failed" unless client.response.status == 303
        abort "reset mail not delivered" unless ActionMailer::Base.deliveries.last.subject == "Choose a new password"
        client.post "/account/requests/reset_password", params: {email_address: "unknown@example.test"}
        abort "unknown-account response leaked" unless client.response.status == 303
        puts "HTML/Turbo/mail/scanner/request contracts verified"
      RUBY
      expect(request_output).to include("HTML/Turbo/mail/scanner/request contracts verified")

      concurrency_output = host.runner(<<~RUBY)
        require "timeout"
        runtime = AddAuth::Rails::Runtime
        ActiveJob::Base.queue_adapter = :test
        def race(count, &operation)
          ready, go = Queue.new, Queue.new
          threads = Array.new(count) do |index|
            Thread.new do
              ActiveRecord::Base.connection_pool.with_connection do
                ready << true
                go.pop
                operation.call(index)
              end
            end
          end
          Timeout.timeout(15) do
            count.times { ready.pop }
            count.times { go << true }
            threads.map(&:value)
          end
        ensure
          threads&.each { |thread| thread.kill if thread.alive? }
        end
        results = race(2) { runtime.accounts.register(identifier: "raced@example.test", password: "race-account-password") }
        abort "registration race leaked account state" unless results.all?(&:success?)
        user = User.find_by!(email_address: "raced@example.test")
        abort "duplicate raced account" unless User.where(email_address: user.email_address).count == 1
        proof = AddAuthAccountToken.find_by!(user_id: user.id, purpose: "confirm")
        token = runtime.accounts.claim_delivery(digest: proof.digest).fetch(:token)
        consumed = race(2) { runtime.accounts.consume(token: token, purpose: :confirm) }
        abort "confirmation had multiple winners" unless consumed.count(&:success?) == 1
        abort "confirmation provisioned more than once" unless user.reload.sign_in_count == 1
        original = runtime.sessions.start(user: user, method: :password)
        runtime.accounts.issue(identifier: user.email_address, purpose: :reset_password)
        proof = AddAuthAccountToken.find_by!(user_id: user.id, purpose: "reset_password")
        token = runtime.accounts.claim_delivery(digest: proof.digest).fetch(:token)
        consumed = race(2) { |index| runtime.accounts.consume(token: token, purpose: :reset_password, password: "raced-password-\#{index}") }
        abort "reset had multiple winners" unless consumed.count(&:success?) == 1
        abort "prior session survived raced reset" if runtime.sessions.resume(signed_value: original.bearer)
        abort "raced password state diverged" unless 2.times.count { |index| user.reload.authenticate("raced-password-\#{index}") } == 1
        AddAuth.configuration.lifecycle.maximum_attempts = 3
        results = race(3) do
          runtime.sessions.authenticate(identifier: user.email_address, password: "wrong") do
            runtime.authenticate_password(identifier: user.email_address, password: "wrong")
          end
        end
        abort "wrong password created a session" unless results.all?(&:nil?)
        abort "concurrent lock threshold was lost" unless user.reload.failed_attempts == 3 && user.locked_at
        proof = AddAuthAccountToken.find_by!(user_id: user.id, purpose: "unlock")
        token = runtime.accounts.claim_delivery(digest: proof.digest).fetch(:token)
        abort "unlock failed" unless runtime.accounts.consume(token: token, purpose: :unlock).success?
        abort "unlock state wrong" unless user.reload.locked_at.nil? && user.failed_attempts == 0
        puts "registration/proof/reset/password-lock races verified"
      RUBY
      expect(concurrency_output).to include("registration/proof/reset/password-lock races verified")

      # Real Chrome exercises CSRF, no-JS forms, Turbo navigation and both layouts.
      browser_output = host.runner(<<~RUBY)
        require #{File.expand_path("../support/browser", __dir__).inspect}
        ActionController::Base.allow_forgery_protection = true
        ActiveJob::Base.queue_adapter = :inline
        %i[turbo html no_js].each do |mode|
          AddAuth.configuration.turbo_enabled = mode == :turbo
          driver = mode == :no_js ? :add_auth_no_js : :add_auth_chrome
          browser = Capybara::Session.new(driver, Rails.application)
          email = "ui-\#{mode}@example.test"
          browser.visit "/account/sign-up"
          raise "form missing" unless browser.has_css?("h1", text: "Create an account")
          raise "Turbo loaded in HTML mode" if mode == :html && browser.evaluate_script("typeof window.Turbo") != "undefined"
          browser.fill_in "Email address", with: email
          browser.fill_in "New password", with: "browser-tested-password"
          browser.click_button "Create account"
          raise "registration navigation failed" unless browser.has_css?("h1", text: "Check your email")
          message = ActionMailer::Base.deliveries.reverse.find { |mail| mail.to == [email] }
          link = URI.parse(message.body.decoded.scan(%r{https://[^[:space:]<>]+}).first)
          browser.visit link.request_uri
          browser.click_button "Confirm this email address"
          raise "confirmation navigation failed" unless browser.has_css?("h1", text: "Sign in")
          browser.current_window.resize_to(390, 844)
          browser.visit "/account/requests/reset_password"
          raise "reset form missing" unless browser.has_css?("h1", text: "Reset your password")
          if driver == :add_auth_chrome
            raise "narrow overflow" unless browser.evaluate_script("document.documentElement.scrollWidth <= window.innerWidth")
          end
          browser.fill_in "Email address", with: email
          browser.click_button "Send account link"
          raise "reset request navigation failed" unless browser.has_css?("h1", text: "Check your email")
          message = ActionMailer::Base.deliveries.reverse.find { |mail| mail.to == [email] && mail.subject == "Choose a new password" }
          browser.visit URI.parse(message.body.decoded.scan(%r{https://[^[:space:]<>]+}).first).request_uri
          browser.fill_in "New password", with: "browser-reset-password"
          browser.click_button "Choose a new password"
          raise "reset completion failed" unless browser.has_css?("h1", text: "Sign in")
          raise "reset redirect retained the proof URL" unless browser.has_current_path?("/sign-in")
          browser.fill_in "Email address", with: email
          browser.fill_in "Password", with: "browser-reset-password"
          browser.within("#add_auth-password-form") { browser.check "Keep me signed in on this browser" }
          browser.click_button "Sign in with password"
          raise "reset password sign-in failed" unless browser.has_text?("Signed in") && browser.has_current_path?("/")
          remembered = Session.where(user_id: User.find_by!(email_address: email).id).order(:id).last
          raise "remembered browser choice lost" unless remembered.remembered && remembered.idle_timeout == 7 * 86_400 &&
            (remembered.expires_at - remembered.authenticated_at).round == 14 * 86_400
          cookie = browser.driver.browser.manage.cookie_named("session_id")
          raise "cookie and server expiry diverged" unless (cookie[:expires].to_f - remembered.expires_at.to_f).abs < 2
          browser.visit "/account/email"
          changed_email = "updated-ui-\#{mode}@example.test"
          browser.fill_in "New email address", with: changed_email
          browser.click_button "Send confirmation link"
          raise "email change skipped step-up" unless browser.has_css?("h1", text: "Verify it’s you")
          browser.fill_in "Current password", with: "wrong-password"
          browser.click_button "Verify with password"
          raise "reauthentication error missing" unless browser.has_css?('[role="alert"]')
          raise "reauthentication failure was not counted" unless User.find_by!(email_address: email).reload.failed_attempts == 1
          browser.fill_in "Current password", with: "browser-reset-password"
          browser.click_button "Verify with password"
          raise "email review missing" unless browser.has_css?("h1", text: "Change your email")
          browser.fill_in "New email address", with: changed_email
          browser.click_button "Send confirmation link"
          raise "pending address changed current login" unless browser.has_css?("h1", text: "Check your email") && User.exists?(email_address: email)
          message = ActionMailer::Base.deliveries.reverse.find { |mail| mail.to == [changed_email] }
          browser.visit URI.parse(message.body.decoded.scan(%r{https://[^[:space:]<>]+}).first).request_uri
          browser.click_button "Confirm this email address"
          raise "reconfirmation did not sign out" unless browser.has_css?("h1", text: "Sign in")
          raise "confirmation redirect retained the proof URL" unless browser.has_current_path?("/sign-in")
          browser.fill_in "Email address", with: changed_email
          browser.fill_in "Password", with: "browser-reset-password"
          browser.click_button "Sign in with password"
          raise "new address sign-in failed" unless browser.has_current_path?("/")
          browser.visit "/account/password"
          browser.fill_in "New password", with: "browser-changed-password"
          browser.click_button "Change password"
          raise "password change skipped step-up" unless browser.has_css?("h1", text: "Verify it’s you")
          browser.fill_in "Current password", with: "browser-reset-password"
          browser.click_button "Verify with password"
          raise "password review missing" unless browser.has_css?("h1", text: "Change your password")
          browser.fill_in "New password", with: "browser-changed-password"
          browser.click_button "Change password"
          raise "password update did not sign out" unless browser.has_css?("h1", text: "Sign in")
          account = User.find_by!(email_address: changed_email).reload
          raise "password update invalid" unless account.authenticate("browser-changed-password") && !account.authenticate("browser-reset-password")
          browser.fill_in "Email address", with: changed_email
          browser.fill_in "Password", with: "browser-changed-password"
          browser.click_button "Sign in with password"
          raise "changed password sign-in failed" unless browser.has_text?("Signed in")
          browser.visit "/account/delete"
          browser.click_button "Delete my account"
          raise "deletion skipped fresh proof" unless browser.has_css?("h1", text: "Verify it’s you")
          browser.fill_in "Current password", with: "browser-changed-password"
          browser.click_button "Verify with password"
          raise "deletion final confirmation missing" unless browser.has_css?("h1", text: "Delete your account")
          raise "reauthentication deleted the account" unless User.exists?(account.id)
          browser.click_button "Delete my account"
          raise "deletion navigation failed" unless browser.has_css?("h1", text: "Sign in")
          raise "deleted account retained" if User.uncached { User.exists?(account.id) }
          raise "deleted account retained sessions" if Session.where(user_id: account.id).exists?
          browser.quit
        end
        puts "Chrome Turbo/HTML/no-JS account journeys verified"
      RUBY
      expect(browser_output).to include("Chrome Turbo/HTML/no-JS account journeys verified")
    ensure
      host&.cleanup
    end
  end
end
