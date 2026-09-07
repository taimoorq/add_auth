# frozen_string_literal: true

# This entry point is used only by local_acceptance.rb with its own loopback
# Redis and SMTP listeners. It never reads the host's production service URLs.
ENV["RAILS_ENV"] = "test"
ENV.delete("DATABASE_URL")
ENV.delete("RAILS_MASTER_KEY")
require_relative "../dummy/config/environment"
require "sidekiq"

redis_port = Integer(ENV.fetch("ADD_AUTH_LOCAL_REDIS_PORT"))
smtp_port = Integer(ENV.fetch("ADD_AUTH_LOCAL_SMTP_PORT"))
raise "invalid local ports" unless [redis_port, smtp_port].all? { |port| (1024..65535).cover?(port) }
url = "redis://127.0.0.1:#{redis_port}/0"
Sidekiq.configure_server do |config|
  config.redis = {url: url}
  config.average_scheduled_poll_interval = 1
end
Sidekiq.configure_client { |config| config.redis = {url: url} }
ActiveJob::Base.queue_adapter = :sidekiq
ActionMailer::Base.delivery_method = :smtp
ActionMailer::Base.smtp_settings = {address: "127.0.0.1", port: smtp_port,
                                   enable_starttls_auto: false, open_timeout: 2, read_timeout: 2}
