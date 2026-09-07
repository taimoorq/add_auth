# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require "timeout"

module Latchkey
  module Core
    module Challenge
      # Small, dependency-free HTTP boundary shared by provider adapters. It
      # deliberately returns protocol states instead of raising provider errors
      # into an authentication request. A provider outage and a malformed
      # response are both unavailable; an invalid user token is rejected.
      class Http
        Response = Data.define(:status, :payload)

        DEFAULT_OPEN_TIMEOUT = 3
        DEFAULT_READ_TIMEOUT = 3
        MAX_TOKEN_BYTES = 2048
        MAX_RESPONSE_BYTES = 16_384
        TOTAL_TIMEOUT = 10

        def initialize(endpoint:, secret_key:, transport: nil, allowed_hosts: nil,
          open_timeout: DEFAULT_OPEN_TIMEOUT, read_timeout: DEFAULT_READ_TIMEOUT)
          @allowed_hosts = allowed_hosts&.map { |host| host.to_s.downcase }&.freeze
          @endpoint = validate_endpoint(endpoint)
          @secret_key = validate_secret(secret_key)
          @transport = transport || method(:request)
          @open_timeout = bounded_timeout(open_timeout, "open_timeout")
          @read_timeout = bounded_timeout(read_timeout, "read_timeout")
        end

        def call(token:, remote_ip: nil)
          return Response.new(status: :rejected, payload: nil) unless valid_token?(token)

          parameters = {"secret" => @secret_key, "response" => token}
          parameters["remoteip"] = remote_ip if remote_ip.is_a?(String) && !remote_ip.empty?
          raw = @transport.call(uri: @endpoint, params: parameters)
          status, body = extract(raw)
          return Response.new(status: :unavailable, payload: nil) unless status.between?(200, 299)

          return Response.new(status: :unavailable, payload: nil) if body.bytesize > MAX_RESPONSE_BYTES
          payload = JSON.parse(body, max_nesting: 10)
          return Response.new(status: :unavailable, payload: nil) unless payload.is_a?(Hash)

          Response.new(status: :ok, payload: payload)
        rescue JSON::ParserError, TypeError, ArgumentError
          Response.new(status: :unavailable, payload: nil)
        rescue
          # Network, TLS and provider client failures must not disclose
          # endpoint details or secret material to the authentication caller.
          Response.new(status: :unavailable, payload: nil)
        end

        def inspect = "#<Latchkey::Core::Challenge::Http [FILTERED]>"

        private

        def validate_endpoint(endpoint)
          uri = URI.parse(endpoint.to_s)
          unless uri.is_a?(URI::HTTPS) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
            raise ArgumentError, "challenge endpoint must be HTTPS"
          end
          if @allowed_hosts && !@allowed_hosts.include?(uri.host.downcase)
            raise ArgumentError, "challenge endpoint host is not allowed"
          end
          uri
        rescue URI::InvalidURIError
          raise ArgumentError, "challenge endpoint must be a valid HTTPS URL"
        end

        def validate_secret(secret)
          value = secret.to_s
          raise ArgumentError, "challenge secret_key must be present" if value.empty? || value.bytesize > 512

          value
        end

        def bounded_timeout(value, name)
          number = Float(value)
          raise ArgumentError, "#{name} must be between 0.1 and 30 seconds" unless number.between?(0.1, 30)

          number
        rescue ArgumentError, TypeError
          raise ArgumentError, "#{name} must be between 0.1 and 30 seconds"
        end

        def valid_token?(token)
          token.is_a?(String) && token.valid_encoding? && token.bytesize.between?(1, MAX_TOKEN_BYTES)
        end

        def extract(raw)
          if raw.respond_to?(:code) && raw.respond_to?(:body)
            [Integer(raw.code), raw.body.to_s]
          elsif raw.is_a?(Array) && raw.size == 2
            [Integer(raw.fetch(0)), raw.fetch(1).to_s]
          else
            raise TypeError, "invalid challenge transport response"
          end
        end

        def request(uri:, params:)
          client = Net::HTTP.new(uri.host, uri.port)
          client.use_ssl = true
          client.open_timeout = @open_timeout
          client.read_timeout = @read_timeout
          request = Net::HTTP::Post.new(uri.request_uri)
          request.set_form_data(params)
          client.write_timeout = @read_timeout
          client.max_retries = 0
          Timeout.timeout(TOTAL_TIMEOUT) do
            result = nil
            client.start do |http|
              http.request(request) do |response|
                body = +""
                response.read_body do |chunk|
                  raise IOError, "challenge response too large" if body.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES
                  body << chunk
                end
                result = [response.code.to_i, body]
              end
            end
            result
          end
        end
      end
    end
  end
end
