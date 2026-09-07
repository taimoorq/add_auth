# frozen_string_literal: true

require "add_auth/core/challenge/http"

module AddAuth
  module Core
    module Challenge
      # Cloudflare Turnstile's server-side Siteverify adapter. The browser
      # widget is optional and host-rendered; this class owns the security
      # decision made from Cloudflare's response.
      class Turnstile < Base
        ENDPOINT = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js"

        def initialize(site_key:, secret_key:, allowed_hostnames: [], transport: nil,
          endpoint: ENDPOINT, open_timeout: Http::DEFAULT_OPEN_TIMEOUT,
          read_timeout: Http::DEFAULT_READ_TIMEOUT)
          @site_key = require_value(site_key, "site_key", max_bytes: 512)
          @allowed_hostnames = normalize_hostnames(allowed_hostnames)
          @http = Http.new(endpoint: endpoint, secret_key: secret_key, allowed_hosts: ["challenges.cloudflare.com"], transport: transport,
            open_timeout: open_timeout, read_timeout: read_timeout)
        end

        attr_reader :site_key

        def script_url = "#{SCRIPT_URL}?render=explicit"
        def stimulus_controller = "add_auth--challenge-turnstile"

        def verify(token:, remote_ip:, action:)
          expected_action = normalize_action(action)
          response = @http.call(token: token, remote_ip: remote_ip)
          return rejected(:invalid_token) if response.status == :rejected
          return unavailable(:verification_service) unless response.status == :ok

          payload = response.payload
          failure = response_failure(payload)
          return failure if failure
          return rejected(:challenge_rejected) unless payload["action"] == expected_action
          return rejected(:challenge_rejected) unless hostname_allowed?(payload["hostname"])

          success
        end
      end
    end
  end
end
