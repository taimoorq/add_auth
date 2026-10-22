# frozen_string_literal: true

module AddAuth
  module Core
    class Intake
      def initialize(digest:, normalizer:, limiter:, challenge:, challenge_on:, challenge_when_unavailable: :closed,
        on_challenge_unavailable: nil)
        @digest, @normalizer, @limiter = digest, normalizer, limiter
        @challenge, @challenge_on = challenge, challenge_on
        @challenge_when_unavailable = challenge_when_unavailable.to_sym
        unless %i[closed open].include?(@challenge_when_unavailable)
          raise ArgumentError, "challenge_when_unavailable must be :closed or :open"
        end
        @on_challenge_unavailable = on_challenge_unavailable
      end

      # An exhausted IP budget stops before the identifier budget, and the
      # identifier is charged only after any configured challenge passes, so
      # other clients cannot spend a target's budget (plan section 18, A4).
      def call(identifier:, ip:, action:, challenge_token: nil)
        value = (identifier.is_a?(String) && identifier.valid_encoding? && identifier.bytesize.between?(1, 254)) ? @normalizer.call(identifier) : ""
        value = "" unless value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, 254)
        return :rate_limited unless @limiter.call(key: @digest.digest("ip:#{ip}:#{action}"), limit: 30)
        return :invalid_credentials if value.to_s.empty?
        rejection = verify_challenge(ip: ip, action: action, challenge_token: challenge_token)
        return rejection if rejection
        return :rate_limited unless @limiter.call(key: @digest.digest("identifier:#{value}:#{action}"), limit: 5)
        value
      end

      # budget separates an IP counter from the challenge action, so a
      # background request cannot spend the budget of an interactive form.
      def anonymous(ip:, action:, challenge_token: nil, budget: action)
        return :rate_limited unless @limiter.call(key: @digest.digest("ip:#{ip}:#{budget}"), limit: 30)
        verify_challenge(ip: ip, action: action, challenge_token: challenge_token) || true
      end

      private def verify_challenge(ip:, action:, challenge_token:)
        if @challenge_on.include?(action)
          result = @challenge.verify(token: challenge_token, remote_ip: ip, action: action)
          if result.unavailable?
            return :challenge_unavailable if @challenge_when_unavailable == :closed
            @on_challenge_unavailable&.call(action: action)
          elsif result.rejected?
            return :challenge_rejected
          end
        end
        nil
      end

      def self.email_available?(config) = config.session.enabled && config.email_link.enabled

      # no-referrer form navigation may send null; this is never a substitute
      # for the adapter's mandatory session-bound CSRF-token verification.
      def self.origin_allowed?(origin:, base_url:)
        origin.nil? || origin == "null" || origin == base_url
      end

      def self.revoke_after_change?(changes)
        (changes.keys.map(&:to_s) & %w[password_digest email_address confirmed_at locked_at disabled_at deleted_at add_auth_authority add_auth_manual_lock]).any?
      end

      def self.notification_after_change(changes)
        return :password_changed if changes.key?("password_digest")
        :email_changed if changes.key?("email_address")
      end
    end
  end
end
