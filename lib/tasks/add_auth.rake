# frozen_string_literal: true

namespace :add_auth do
  desc "Check installed AddAuth authentication, delivery and maintenance wiring"
  task doctor: :environment do
    require "add_auth/rails/doctor"
    doctor = AddAuth::Rails::Doctor.new
    problems = doctor.call
    Array(doctor.ejections).each do |entry|
      puts "Customized: #{entry[:path]}" if entry[:customized]
      puts entry[:diff] if entry[:diff]
    end
    puts problems.empty? ? "AddAuth configuration checks passed." : problems.join("\n")
    abort "AddAuth configuration needs attention" if problems.any?
  end

  desc "Run bounded delivery recovery and retention; schedule at least every minute"
  task deliver_pending: :environment do
    require "add_auth/rails/stores/maintenance"
    models = {}
    models[:session] = ::Session if AddAuth.configuration.session.enabled && defined?(::Session)
    models[:ceremony] = ::AddAuthCeremony if defined?(::AddAuthCeremony)
    models[:email] = ::AddAuthSignInToken if defined?(::AddAuthSignInToken)
    models[:notification] = ::AddAuthSecurityEvent if defined?(::AddAuthSecurityEvent)
    stores = models.filter_map do |kind, model|
      [kind, AddAuth::Rails::Stores::Maintenance.new(model: model, kind: kind)] if model.table_exists?
    end.to_h
    jobs = {email: AddAuth::EmailDeliveryJob, notification: AddAuth::SecurityNotificationJob}
    enqueue = lambda do |kind, id|
      raise AddAuth::Error, "maintenance enqueue failed" unless jobs.fetch(kind).perform_later(id)
    end
    ActiveSupport::Notifications.instrument("maintenance.add_auth") do |payload|
      payload.merge!(AddAuth::Core::Maintenance.new(stores: stores,
        options: AddAuth.configuration.maintenance, enqueue: enqueue).call)
      AddAuth::Rails::Runtime.record_maintenance
    end
  end
end
