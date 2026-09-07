# frozen_string_literal: true

namespace :add_auth do
  desc "Check installed AddAuth session, email and challenge wiring"
  task doctor: :environment do
    require "add_auth/rails/doctor"
    doctor = AddAuth::Rails::Doctor.new
    problems = doctor.call
    Array(doctor.ejections).each do |entry|
      puts "Customized: #{entry[:path]}" if entry[:customized]
      puts entry[:diff] if entry[:diff]
    end
    puts problems.empty? ? "AddAuth session/email/challenge checks passed." : problems.join("\n")
    abort "AddAuth configuration needs attention" if problems.any?
  end

  desc "Recover pending email delivery and erase expired delivery secrets; schedule at least every minute"
  task deliver_pending: :environment do
    now = Time.current
    if defined?(::AddAuthCeremony) && ::AddAuthCeremony.table_exists?
      ::AddAuthCeremony.where("expires_at <= ?", now).delete_all
    end
    stores = []
    stores << [::AddAuthSignInToken, AddAuth::EmailDeliveryJob] if defined?(::AddAuthSignInToken) && ::AddAuthSignInToken.table_exists?
    stores << [::AddAuthSecurityEvent, AddAuth::SecurityNotificationJob] if defined?(::AddAuthSecurityEvent) && ::AddAuthSecurityEvent.table_exists?
    stores.each do |model, job|
      model.where("expires_at <= ?", now).where.not(delivery_payload: nil).update_all(delivery_payload: nil)
      model.where(revoked_at: nil, delivered_at: nil)
        .where.not(delivery_payload: nil).where("expires_at > ?", now)
        .where("delivery_lease_until IS NULL OR delivery_lease_until <= ?", now).find_each do |record|
        job.perform_later(record.id)
      end
    end
    AddAuth::Rails::Runtime.record_maintenance
  end
end
