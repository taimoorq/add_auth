# frozen_string_literal: true

require_relative "isolated_host"

class DeviseSourceHost < IsolatedHost
  def prepare(profile: :standard)
    install(self.class.candidate(directory), label: "candidate", extra_gems: ["devise", "pg"])
    run("generate", "devise:install")
    if profile == :uuid
      require "pg"
      require "securerandom"
      @schema = "add_auth_fixture_#{SecureRandom.hex(8)}"
      File.write(File.join(root, "config/database.yml"), <<~YAML)
        test:
          adapter: postgresql
          database: add_auth_migration_test
          host: localhost
          schema_search_path: #{@schema}
      YAML
      # The database name is deliberately fixed and distinct from spec/dummy.
      run("db:create")
      PG.connect(dbname: "add_auth_migration_test", host: "localhost") do |connection|
        connection.exec("CREATE SCHEMA #{@schema}")
      end
      run("generate", "devise", "User", "--primary-key-type=uuid")
    else
      run("generate", "devise", "User")
    end
    user_path = File.join(root, "app/models/user.rb")
    File.write(user_path, File.read(user_path).sub(":validatable", ":validatable, :confirmable, :lockable, :trackable"))
    migration = Dir[File.join(root, "db/migrate/*devise_create_users.rb")].fetch(0)
    source = File.read(migration)
    # Exercise actual generated Devise storage plus its optional module columns.
    source = source.gsub(/^(\s*)# (t\.(?:string|datetime|integer|inet)\s+:(?:confirmation_token|confirmed_at|confirmation_sent_at|unconfirmed_email|failed_attempts|unlock_token|locked_at|sign_in_count|current_sign_in_at|last_sign_in_at|current_sign_in_ip|last_sign_in_ip).*?)$/, '\1\2')
    File.write(migration, source)
    run("db:migrate")
    File.open(File.join(root, "config/environments/test.rb"), "a") do |file|
      file.puts "Rails.application.routes.default_url_options[:host] = 'example.test'"
      file.puts "Rails.application.configure { config.action_mailer.default_url_options = {host: 'example.test'} }"
    end
    if profile == :aligned
      runner(<<~RUBY)
        ActiveRecord::Schema.define do
          add_column :users, :email_address, :string
          add_column :users, :password_digest, :string
          create_table :sessions do |t|
            t.references :user, null: false, foreign_key: true
            t.string :ip_address
            t.string :user_agent
            t.timestamps
          end
        end
      RUBY
      File.write(File.join(root, "app/models/session.rb"), "class Session < ApplicationRecord; belongs_to :user; end\n")
      File.write(File.join(root, "app/models/current.rb"), "class Current < ActiveSupport::CurrentAttributes; attribute :session; end\n")
      File.write(File.join(root, "app/controllers/concerns/authentication.rb"), "module Authentication; extend ActiveSupport::Concern; end\n")
      File.open(user_path, "a") do |file|
        file.puts <<~RUBY
          User.class_eval do
            legacy_writer = instance_method(:password=)
            has_secure_password validations: false
            normalizes :email_address, with: ->(email) { email.strip.downcase }
            define_method(:password=) do |value|
              legacy_writer.bind_call(self, value)
              self.password_digest = encrypted_password
            end
            before_validation { self.email_address = email }
          end
        RUBY
      end
    end
    runner(<<~RUBY)
      ActionMailer::Base.perform_deliveries = false
      User.stretches = 4
      User.pepper = "synthetic-secret-pepper" if #{profile == :peppered}
      3.times do |index|
        user = User.new(email: "source-\#{index}@example.test", password: "source-password")
        user.skip_confirmation_notification!
        user.confirmed_at = Time.current unless index == 1
        user.locked_at = Time.current if index == 2
        user.save!
      end
      abort "source verifier failed" unless User.first.valid_password?("source-password")
      abort "wrong source password accepted" if User.first.valid_password?("wrong")
      puts "populated source verified"
    RUBY
    if profile == :peppered
      File.open(File.join(root, "config/initializers/devise.rb"), "a") { |file| file.puts 'Devise.pepper = "synthetic-secret-pepper"' }
    end
    if profile == :custom
      File.open(user_path, "a") { |file| file.puts "class User; def valid_password?(password); super; end; end" }
    end
    if profile == :uuid
      runner(<<~RUBY)
        ActiveRecord::Schema.define do
          create_table :oauth_identities do |t|
            t.references :user, type: :uuid, foreign_key: true
            t.string :provider
            t.string :uid
          end
        end
        connection = User.connection
        connection.execute("INSERT INTO oauth_identities (user_id, provider, uid) VALUES (\#{connection.quote(User.first.id)}, 'synthetic', 'private-subject')")
      RUBY
    end
  end

  def cleanup
    return unless @schema
    PG.connect(dbname: "add_auth_migration_test", host: "localhost") do |connection|
      connection.exec("DROP SCHEMA #{@schema} CASCADE")
    end
  end

  def prepare_accounts
    run("generate", "add_auth:devise_accounts")
    run("db:migrate")
    runner(<<~RUBY)
      require "add_auth/core/migration/account_adoption"
      require "add_auth/rails/migration/account_store"
      store = AddAuth::Rails::Migration::AccountStore.new(user_model: User)
      result = AddAuth::Core::Migration::AccountAdoption.new(store: store).call
      abort "account preparation incomplete" unless result[:prepared] == 3 && result[:conflicts] == 0
      abort "source password changed" unless User.find_by(email: "source-0@example.test").valid_password?("source-password")
      puts "account preparation verified"
    RUBY
  end

  def password_destination(profile:)
    reference_directory = File.join(directory, "reference")
    FileUtils.mkdir_p(reference_directory)
    reference = IsolatedHost.new(reference_directory)
    artifact = self.class.candidate(directory)
    reference.install(artifact, label: "package")
    reference.run("generate", "authentication")
    # Adopt actual Rails-generator model/controller/cookie contracts in this
    # disposable fixture, retaining the populated source table and primary keys.
    %w[app/controllers app/models app/mailers app/views config/routes.rb].each do |path|
      source = File.join(reference.root, path)
      destination = File.join(root, path)
      FileUtils.rm_rf(destination)
      FileUtils.cp_r(source, destination)
    end
    session_migration = Dir[File.join(reference.root, "db/migrate/*_create_sessions.rb")].fetch(0)
    content = File.read(session_migration).sub("t.references :user,", "t.references :user, type: AddAuth::Rails::Migration::KeyType.for(connection, :users),")
    File.write(File.join(root, "db/migrate", File.basename(session_migration)), %(require "add_auth/rails/migration/key_type"\n#{content})) unless profile == :aligned
    FileUtils.rm_f(File.join(root, "config/initializers/devise.rb"))
    install(artifact, label: "destination", extra_gems: ["pg", "capybara", "selenium-webdriver", "rspec-rails"])
    run("db:migrate")
    run("generate", "add_auth:passkeys")
    configure
    File.open(File.join(root, "app/models/user.rb"), "a") do |file|
      file.puts 'require "add_auth/rails/password_adoption"'
      file.puts "User.include AddAuth::Rails::PasswordAdoption"
      # The retained source column still has Devise's non-null/unique contract.
      # This fixture maps its post-switch projection explicitly; the resumable
      # migration bridge is a separate acceptance gate.
      file.puts "User.before_validation { self.email = email_address }"
    end
    File.open(File.join(root, "config/initializers/add_auth.rb"), "a") do |file|
      file.puts <<~RUBY
        require "add_auth/core/passwords/legacy_bcrypt"
        AddAuth.configuration.legacy_password_verifier = AddAuth::Core::Passwords::LegacyBcrypt.new(pepper: -> { #{(profile == :peppered) ? '"synthetic-secret-pepper"' : "nil"} })
        AddAuth.configuration.eligible = ->(user) { !!user.confirmed_at && !user.locked_at }
      RUBY
    end
    run("db:migrate")
    runner('User.update_all(add_auth_authority: "add_auth")')
  end
end
