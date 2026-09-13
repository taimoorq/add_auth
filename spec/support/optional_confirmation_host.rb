# frozen_string_literal: true

require_relative "isolated_host"

module OptionalConfirmationHost
  module_function

  def prepare(host)
    host.run("generate", "add_auth:accounts", "--no-email-link")
    migrations = Dir[File.join(host.root, "db/migrate/*")]
    initializer = File.read(File.join(host.root, "config/initializers/add_auth.rb"))
    host.run("generate", "add_auth:accounts", "--no-email-link")
    raise "repeat generation changed migrations" unless Dir[File.join(host.root, "db/migrate/*")] == migrations
    raise "repeat generation changed settings" unless File.read(File.join(host.root, "config/initializers/add_auth.rb")) == initializer
    host.run("db:migrate")
    host.configure
    File.write(File.join(host.root, "app/controllers/optional_home_controller.rb"), <<~SOURCE)
      class OptionalHomeController < ApplicationController
        def index
          render html: "<h1>Signed in</h1><p>\#{ERB::Util.html_escape(Current.user.email_address)}</p>".html_safe, layout: false
        end
      end
    SOURCE
    routes = File.join(host.root, "config/routes.rb")
    File.write(routes, File.read(routes).sub("Rails.application.routes.draw do", "Rails.application.routes.draw do\n  root to: 'optional_home#index'"))
    host.runner(<<~SOURCE)
      ActiveRecord::Schema.define do
        add_column :users, :provision_count, :integer, default: 0, null: false
        add_column :users, :access_state, :string, default: "active"
        add_column :users, :add_auth_strict, :boolean, default: false unless column_exists?(:users, :add_auth_strict)
      end
    SOURCE
    File.open(File.join(host.root, "config/initializers/add_auth.rb"), "a") do |file|
      file.puts <<~SOURCE
        AddAuth.configure do |config|
          config.lifecycle.enabled = true
          config.eligible = ->(user) { user.access_state == "active" }
          config.lifecycle.provision = ->(user) { user.update_columns(provision_count: user.provision_count + 1) }
          config.trusted_recovery_address = ->(user) { user.email_address }
        end
      SOURCE
    end
    if ENV["ADD_AUTH_EJECT_UI"] == "1"
      host.runner(<<~SOURCE)
        require "add_auth/rails/ejection"
        ejection = AddAuth::Rails::Ejection.new(host_root: Rails.root)
        %i[views controllers javascript mailer_views].each { |kind| ejection.install(kind: kind) }
        abort "account ejection absent" unless File.exist?(Rails.root.join("app/controllers/add_auth/accounts_controller.rb"))
      SOURCE
    end
  end

  def verify(host)
    path = File.expand_path("../acceptance/optional_confirmation.rb", __dir__)
    host.runner("require #{path.inspect}")
  end
end
