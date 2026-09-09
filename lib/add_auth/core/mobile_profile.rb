# frozen_string_literal: true

require "uri"

module AddAuth
  module Core
    # Host-selected finite API sessions. Client identifiers select configuration,
    # never prove application identity or authorize an account.
    class MobileProfile
      PATTERN = /\Aam1:[A-Za-z0-9_-]{43}\z/
      attr_reader :lifetime, :idle_timeout, :clients

      def initialize(lifetime:, idle_timeout:, clients:, callbacks: {})
        unless [lifetime, idle_timeout].all? { |value| value.is_a?(Integer) && value.between?(60, 90 * 86_400) } && idle_timeout <= lifetime
          raise ArgumentError, "mobile timeouts must be explicit, finite and at most 90 days"
        end
        unless clients.is_a?(Array) && clients.size.between?(1, 32) && clients.uniq == clients &&
            clients.all? { |value| value.is_a?(String) && value.match?(/\A[a-z][a-z0-9_-]{0,63}\z/) }
          raise ArgumentError, "register bounded mobile client identifiers"
        end
        @lifetime, @idle_timeout = lifetime, idle_timeout
        @clients = clients.map { |client| client.dup.freeze }.freeze
        unless callbacks.is_a?(Hash) && callbacks.all? { |client, callback| client?(client) && valid_callback?(callback) }
          raise ArgumentError, "register exact mobile callbacks without query, fragment or credentials"
        end
        @callbacks = callbacks.to_h { |client, callback| [client.dup.freeze, callback.dup.freeze] }.freeze
        freeze
      end

      def client?(id) = id.is_a?(String) && clients.include?(id)
      def callback(client_id) = @callbacks[client_id]
      def bearer = "am1:#{SecureRandom.urlsafe_base64(32)}"

      private

      def valid_callback?(value)
        return false unless value.is_a?(String) && value.ascii_only? && value.bytesize.between?(10, 2048) && !value.match?(/[\x00-\x20\x7f\\%]/)
        uri = URI.parse(value)
        uri.scheme && !%w[http javascript data file].include?(uri.scheme.downcase) &&
          uri.host && !uri.host.empty? && uri.path && !uri.path.empty? && !uri.userinfo && !uri.query && !uri.fragment
      rescue URI::InvalidURIError
        false
      end
    end
  end
end
