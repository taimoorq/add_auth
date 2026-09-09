# frozen_string_literal: true

require "net/http"
require "json"

module AddAuth
  module Rails
    module ProviderLibraries
      class AppleJwks
        URL = URI("https://appleid.apple.com/auth/keys").freeze
        CACHE_KEY = "add_auth:apple:jwks:v1"
        MAX_BYTES = 65_536

        def initialize(cache:)
          @cache = cache
        end

        # ruby-jwt's key finder requests one invalidation on an unknown kid.
        # No request/header claim selects a URL or changes TLS verification.
        def call(options = {})
          cached = cache_operation { @cache.read(CACHE_KEY) } unless options[:invalidate]
          return cached if valid?(cached)
          keys = fetch
          cache_operation { @cache.write(CACHE_KEY, keys, expires_in: 3600) }
          keys
        end

        private

        def cache_operation
          yield
        rescue
          raise AddAuth::Error, "Apple signing keys unavailable", cause: nil
        end

        def fetch
          body = +""
          Timeout.timeout(5) do
            Net::HTTP.start(URL.host, URL.port, use_ssl: true, open_timeout: 2, read_timeout: 3, write_timeout: 3) do |http|
              http.max_retries = 0
              http.request(Net::HTTP::Get.new(URL.request_uri)) do |response|
                raise AddAuth::Error, "Apple signing keys unavailable" unless response.code == "200"
                response.read_body do |part|
                  raise AddAuth::Error, "Apple signing keys unavailable" if body.bytesize + part.bytesize > MAX_BYTES
                  body << part
                end
              end
            end
          end
          keys = JSON.parse(body)
          raise AddAuth::Error, "Apple signing keys unavailable" unless valid?(keys)
          keys
        rescue JSON::ParserError, Timeout::Error, SocketError, SystemCallError, IOError, OpenSSL::SSL::SSLError
          raise AddAuth::Error, "Apple signing keys unavailable", cause: nil
        end

        def valid?(value)
          value.is_a?(Hash) && value["keys"].is_a?(Array) && value["keys"].size.between?(1, 16) &&
            value["keys"].all? { |key|
              key.is_a?(Hash) && key["kty"] == "RSA" && key["alg"] == "RS256" &&
                key["kid"].is_a?(String) && key["kid"].bytesize.between?(1, 128) && key["n"].is_a?(String) && key["n"].bytesize.between?(1, 1024) &&
                key["e"].is_a?(String) && key["e"].bytesize.between?(1, 16)
            } && value["keys"].map { |key| key["kid"] }.uniq.length == value["keys"].length
        end
      end
    end
  end
end
