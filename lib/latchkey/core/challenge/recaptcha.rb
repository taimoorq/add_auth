# frozen_string_literal: true

require "latchkey/core/challenge/http"

module Latchkey
  module Core
    module Challenge
      # Google reCAPTCHA Siteverify adapter for both v2 checkbox and v3 score
      # keys. v2 deliberately ignores action/score fields because Google does
      # not make the v3 contract available for that mode.
      class Recaptcha < Base
        ENDPOINT = "https://www.google.com/recaptcha/api/siteverify"
        SCRIPT_URL = "https://www.google.com/recaptcha/api.js"

        def initialize(site_key:, secret_key:, version: :v3, allowed_hostnames: [], minimum_score: 0.5,
          expected_action: nil, transport: nil, endpoint: ENDPOINT,
          open_timeout: Http::DEFAULT_OPEN_TIMEOUT, read_timeout: Http::DEFAULT_READ_TIMEOUT)
          @site_key = require_value(site_key, "site_key", max_bytes: 512)
          @version = normalize_version(version)
          @allowed_hostnames = normalize_hostnames(allowed_hostnames)
          @minimum_score = normalize_score(minimum_score)
          @expected_action = expected_action.nil? ? nil : normalize_action(expected_action)
          @http = Http.new(endpoint: endpoint, secret_key: secret_key, allowed_hosts: ["www.google.com"], transport: transport,
            open_timeout: open_timeout, read_timeout: read_timeout)
        end

        attr_reader :site_key, :version, :minimum_score, :expected_action

        def script_url = "#{SCRIPT_URL}?render=#{(@version == :v3) ? URI.encode_www_form_component(site_key) : "explicit"}"
        def stimulus_controller = "latchkey--challenge-recaptcha"

        def verify(token:, remote_ip:, action:)
          response = @http.call(token: token, remote_ip: remote_ip)
          return rejected(:invalid_token) if response.status == :rejected
          return unavailable(:verification_service) unless response.status == :ok

          payload = response.payload
          failure = response_failure(payload)
          return failure if failure
          return rejected(:challenge_rejected) unless hostname_allowed?(payload["hostname"])
          return success if @version == :v2

          expected = @expected_action || normalize_action(action)
          return rejected(:challenge_rejected) unless payload["action"] == expected
          return rejected(:challenge_rejected) unless score_at_least?(payload["score"])

          success
        end

        private

        def normalize_version(version)
          value = version.to_sym
          raise ArgumentError, "reCAPTCHA version must be :v2 or :v3" unless %i[v2 v3].include?(value)

          value
        rescue NoMethodError
          raise ArgumentError, "reCAPTCHA version must be :v2 or :v3"
        end

        def normalize_score(score)
          value = Float(score)
          raise ArgumentError, "minimum_score must be between 0 and 1" unless value.between?(0, 1)

          value
        rescue ArgumentError, TypeError
          raise ArgumentError, "minimum_score must be between 0 and 1"
        end

        def score_at_least?(score)
          score.is_a?(Numeric) && score.finite? && score.between?(@minimum_score, 1)
        end
      end
    end
  end
end
