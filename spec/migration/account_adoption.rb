# frozen_string_literal: true

require "spec_helper"
require "rails"
require "devise"
require_relative "../support/devise_source_host"

RSpec.describe "Devise account adoption" do
  profiles = (ENV["ADD_AUTH_MIGRATION_POSTGRES"] == "1") ? [:uuid] : %i[standard aligned peppered]
  profiles.each do |profile|
    it "preserves #{profile} account ownership and passwords in the real Rails-generator destination" do
      Dir.mktmpdir("add-auth-adoption-") do |directory|
        host = DeviseSourceHost.new(directory)
        host.prepare(profile: profile)
        host.prepare_accounts
        host.password_destination(profile: profile)
        output = host.runner(<<~RUBY)
          abort "Devise remains in destination bundle" if Gem.loaded_specs.key?("devise") || defined?(Devise)
          user = User.find_by!(email_address: "source-0@example.test")
          abort "account id changed" unless User.where(id: user.id, email: user.email_address).exists? && User.count == 3
          abort "legacy password failed" unless User.authenticate_by(email_address: user.email_address, password: "source-password")
          abort "wrong password accepted" if User.authenticate_by(email_address: user.email_address, password: "wrong")
          client = ActionDispatch::Integration::Session.new(Rails.application)
          client.post "/sign-in/password", params: {email_address: user.email_address, password: "source-password"}
          abort "destination sign-in failed" unless client.response.status == 303 && Session.count == 1
          session = Session.last
          abort "wrong account ownership" unless session.user_id == user.id
          abort "successful sign-in did not retire legacy verifier" unless user.reload.add_auth_password_scheme == "rails"
          abort "rehashed password no longer works" unless user.authenticate("source-password")
          %w[add_auth_credentials add_auth_sign_in_tokens add_auth_ceremonies add_auth_security_events].each do |table|
            expected = User.columns_hash.fetch("id").type
            actual = User.connection.columns(table).find { |column| column.name == "user_id" }.type
            abort "account FK type mismatch" unless expected == actual
          end
          user.update!(password: "replacement-password")
          abort "legacy profile not retired" unless user.reload.add_auth_password_scheme == "rails"
          abort "old session survives password change" unless session.reload.revoked_at
          abort "old password fallback" if User.authenticate_by(email_address: user.email_address, password: "source-password")
          abort "new Rails password failed" unless User.authenticate_by(email_address: user.email_address, password: "replacement-password")
          before = Session.count
          client.post "/sign-in/password", params: {email_address: "source-1@example.test", password: "source-password"}
          abort "unconfirmed source account admitted" unless Session.count == before
          client.post "/sign-in/password", params: {email_address: "source-2@example.test", password: "source-password"}
          abort "locked source account admitted" unless Session.count == before
          puts "account/password/request/FK adoption verified"
        RUBY
        expect(output).to include("account/password/request/FK adoption verified")
      ensure
        host&.cleanup
      end
    end
  end

  it "resumes bounded conversion and detects source edits and identifier collisions" do
    Dir.mktmpdir("add-auth-adoption-races-") do |directory|
      host = DeviseSourceHost.new(directory)
      host.prepare(profile: :standard)
      host.run("generate", "add_auth:devise_accounts")
      host.run("db:migrate")
      output = host.runner(<<~RUBY)
        require "add_auth/core/migration/account_adoption"
        require "add_auth/rails/migration/account_store"
        store = AddAuth::Rails::Migration::AccountStore.new(user_model: User)
        conversion = AddAuth::Core::Migration::AccountAdoption.new(store: store)
        first = conversion.call(limit: 1)
        abort "batch was not bounded" unless first[:prepared] == 1 && first[:next_cursor]
        second = conversion.call(after: first[:next_cursor], limit: 1)
        third = conversion.call(after: second[:next_cursor], limit: 1)
        abort "pagination lost accounts" unless second[:prepared] == 1 && third[:prepared] == 1 && third[:next_cursor].nil?
        abort "repeat was not idempotent" unless conversion.call[:unchanged] == 3
        first_user, second_user = User.order(:id).limit(2).to_a
        second_user.update_columns(email: first_user.email.upcase)
        collision = conversion.call
        abort "normalization conflict missing" unless collision[:conflicts] == 1 && User.count == 3
        original_page = store.method(:source_page)
        store.define_singleton_method(:source_page) do |**args|
          result = original_page.call(**args)
          User.find(result.first[:id]).update!(password: "concurrently-replaced")
          result
        end
        raced = conversion.call
        abort "source edit was overwritten" unless raced[:changed_source] == 1
        abort "new source password lost" unless User.find(first_user.id).valid_password?("concurrently-replaced")
        abort "migration sent mail" unless ActionMailer::Base.deliveries.empty?
        puts "bounded conversion/conflict/source-edit verified"
      RUBY
      expect(output).to include("bounded conversion/conflict/source-edit verified")
    end
  end
end
