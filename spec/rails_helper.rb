# frozen_string_literal: true

ENV["RAILS_ENV"] = "test"
# Never consume the developer's DATABASE_URL or Rails credential key in specs.
ENV.delete("DATABASE_URL")
ENV.delete("RAILS_MASTER_KEY")
require "spec_helper"
require "fileutils"
if ENV["LATCHKEY_EJECT_UI"] == "1"
  require "latchkey/rails/ejection"
  host = File.expand_path("dummy", __dir__)
  ejection = Latchkey::Rails::Ejection.new(host_root: host)
  inventory = %i[views controllers javascript mailer_views].flat_map { |kind| ejection.files(kind: kind).keys }.uniq
  originals = (inventory + [Latchkey::Rails::Ejection::MANIFEST]).to_h do |path|
    full = File.join(host, path)
    [full, File.file?(full) ? File.binread(full) : nil]
  end
  at_exit do
    originals.each { |path, content| content ? File.binwrite(path, content) : FileUtils.rm_f(path) }
  end
  %i[views controllers javascript mailer_views].each { |kind| ejection.install(kind: kind) }
end
require_relative "dummy/config/environment"
require "rspec/rails"
require "generators/latchkey/email_tokens/email_tokens_generator"

# Exercise the actual generator; migrations and generated model are the fixture.
Latchkey::Generators::EmailTokensGenerator.start([], destination_root: Rails.root.to_s, quiet: true)
# Keep the generated foundation before the checked-in extension migrations.
# A fresh checkout otherwise stamps it with today's time, after its dependents.
token_migration = Dir[Rails.root.join("db/migrate/*_create_latchkey_sign_in_tokens.rb")].fetch(0)
fixture_migration = Rails.root.join("db/migrate/20260906231226_create_latchkey_sign_in_tokens.rb").to_s
FileUtils.mv(token_migration, fixture_migration) unless token_migration == fixture_migration
require Rails.root.join("app/models/latchkey_sign_in_token").to_s
FileUtils.mkdir_p(Rails.root.join("storage"))
if ENV["LATCHKEY_TEST_DATABASE_URL"]
  test_url = URI.parse(ENV.fetch("LATCHKEY_TEST_DATABASE_URL"))
  unless %w[postgres postgresql].include?(test_url.scheme) && test_url.path == "/latchkey_test"
    abort "LATCHKEY_TEST_DATABASE_URL must name the disposable latchkey_test PostgreSQL database"
  end
  ActiveRecord::Base.establish_connection(ENV.fetch("LATCHKEY_TEST_DATABASE_URL"))
end
ActiveRecord::Migration.verbose = false
ActiveRecord::MigrationContext.new(Rails.root.join("db/migrate")).migrate

RSpec.configure do |config|
  config.use_transactional_fixtures = false
  config.before(:each, type: :request) { Current.reset }
  config.before(:each, :database) do
    Latchkey.configuration.rate_limit_store.clear
    ActiveJob::Base.queue_adapter.enqueued_jobs.clear
    ActionMailer::Base.deliveries.clear
    LatchkeySecurityEvent.delete_all
    LatchkeyCeremony.delete_all
    LatchkeyCredential.delete_all
    LatchkeySignInToken.delete_all
    Session.delete_all
    User.delete_all
  end
  config.after(:each, :database) { Current.reset }
end
