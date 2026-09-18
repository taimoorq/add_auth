# frozen_string_literal: true

require "spec_helper"
require "rails"
require "pg"
require_relative "../support/isolated_host"

RSpec.describe "Configured authentication primary keys in a generated PostgreSQL host" do
  [[:uuid, :uuid, :uuid], [:uuid, :bigint, :uuid], [:bigint, :uuid, :bigint]].each do |user_type, session_type, table_type|
    it "runs with #{user_type} users, #{session_type} sessions and #{table_type} authentication tables" do
      database = ENV.fetch("ADD_AUTH_KEYS_DATABASE_URL")
      uri = URI(database)
      raise "Use disposable add_auth_external_test PostgreSQL database" unless %w[postgres postgresql].include?(uri.scheme) && uri.path == "/add_auth_external_test" && uri.query.nil?
      connection = PG.connect(database)
      schema = "authentication_keys_#{SecureRandom.hex(8)}"
      connection.exec("CREATE SCHEMA #{schema}")
      Dir.mktmpdir("add-auth-keys-") do |directory|
        host = IsolatedHost.new(directory)
        host.environment["DATABASE_URL"] = "#{database}?schema_search_path=#{schema}"
        host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: %w[pg rspec-rails capybara selenium-webdriver])
        configuration = File.join(host.root, "config/initializers/generators.rb")
        File.write(configuration, "Rails.application.config.generators { |g| g.orm :active_record, primary_key_type: :#{user_type} }\n")
        host.run("generate", "authentication")
        if session_type != user_type
          path = Dir[File.join(host.root, "db/migrate/*_create_sessions.rb")].fetch(0)
          File.write(path, File.read(path).sub("create_table :sessions, id: :#{user_type}", "create_table :sessions, id: :#{session_type}"))
        end
        File.write(configuration, "Rails.application.config.generators { |g| g.orm :active_record, primary_key_type: :#{table_type} }\n")
        %w[accounts passkeys external_identities mobile_sessions].each { |name| host.run("generate", "add_auth:#{name}") }
        migrations = Dir[File.join(host.root, "db/migrate/*")].to_h { |path| [path, File.read(path)] }
        %w[accounts passkeys external_identities mobile_sessions].each { |name| host.run("generate", "add_auth:#{name}") }
        expect(migrations).to eq(Dir[File.join(host.root, "db/migrate/*")].to_h { |path| [path, File.read(path)] })
        # A later config edit cannot change already generated migrations.
        File.write(configuration, "Rails.application.config.generators { |g| g.orm :active_record, primary_key_type: :#{(table_type == :uuid) ? :bigint : :uuid} }\n")
        host.run("db:migrate")
        host.configure
        File.open(File.join(host.root, "config/initializers/add_auth.rb"), "a") do |file|
          file.puts <<~RUBY
            AddAuth.configure do |config|
              config.mobile.enabled = true
              config.mobile.clients = ["android"]
              config.mobile.lifetime = 3600
              config.mobile.idle_timeout = 1800
            end
          RUBY
        end
        File.write(File.join(host.root, "app/controllers/keys_home_controller.rb"), <<~RUBY)
          class KeysHomeController < ApplicationController
            def index
              render html: "<h1>Signed in</h1>".html_safe, layout: false
            end
          end
        RUBY
        routes = File.join(host.root, "config/routes.rb")
        File.write(routes, File.read(routes).sub("Rails.application.routes.draw do", "Rails.application.routes.draw do\n  root to: 'keys_home#index'"))
        expect(host.runner(<<~RUBY)).to include("schema keys verified")
          expected = {"users" => :#{user_type}, "sessions" => :#{session_type}}
          connection = ActiveRecord::Base.connection
          tables = connection.tables.select { |table| table.start_with?("add_auth_") }
          abort "missing authentication tables" unless tables.size == 9
          tables.each { |table| expected[table] = :#{table_type} }
          expected.each do |table, type|
            key = connection.columns(table).find { |column| column.name == "id" }
            actual = (key.type == :integer && key.limit == 8) ? :bigint : key.type
            abort "wrong primary key on \#{table}: \#{actual}" unless actual == type
            connection.foreign_keys(table).each do |fk|
              source = connection.columns(table).find { |column| column.name == fk.column }
              target = connection.columns(fk.to_table).find { |column| column.name == "id" }
              abort "wrong reference on \#{table}.\#{fk.column}" unless [source.type, source.limit] == [target.type, target.limit]
            end
          end
          abort "missing cursor index" unless connection.indexes(:sessions).any? { |index| index.columns == %w[user_id created_at id] }
          puts "schema keys verified"
        RUBY
        acceptance = File.expand_path("../acceptance/session_keys.rb", __dir__)
        output = host.runner("require #{acceptance.inspect}")
        expect(output).to include("0 failures")
        puts "Bundled #{user_type}/#{session_type}/#{table_type}: #{output.lines.grep(/examples, .*failures/).join.strip}"
        # Ejection is verified in the same generated host against the same keys.
        if user_type == :uuid && session_type == :uuid
          host.runner(<<~RUBY)
            require "add_auth/rails/ejection"
            ejection = AddAuth::Rails::Ejection.new(host_root: Rails.root)
            %i[views controllers javascript].each { |kind| ejection.install(kind: kind) }
          RUBY
          output = host.runner("require #{acceptance.inspect}")
          expect(output).to include("0 failures")
          puts "Ejected UUID: #{output.lines.grep(/examples, .*failures/).join.strip}"
        end
      end
    ensure
      connection&.exec("DROP SCHEMA IF EXISTS #{schema} CASCADE") if schema
      connection&.close
    end
  end
end
