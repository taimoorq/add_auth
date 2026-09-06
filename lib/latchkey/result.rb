# frozen_string_literal: true

module Latchkey
  # Every Core entry point returns one of these instead of raising for an
  # authentication outcome (it still raises for programmer error) or
  # returning a bare boolean. See docs/authentication-gem-plan.md section 2,
  # "Everything returns a Result," for the rationale: a closed set of reason
  # codes is something a host can exhaustively match/translate, and it can't
  # accidentally leak *which* half of a credential check failed.
  class Result
    # Closed set. Adding a value here is a deliberate, documented decision --
    # hosts are expected to `case`/`in` over this list.
    REASONS = %i[
      invalid_credentials  unknown_identifier   unconfirmed
      locked               disabled             expired_token
      consumed_token       revoked_token        challenge_rejected
      challenge_unavailable  rate_limited       origin_mismatch
      counter_regression   elevation_required
    ].freeze

    attr_reader :user, :strategy, :credential, :reason

    def self.success(user:, strategy:, credential: nil)
      new(success: true, user:, strategy:, credential:)
    end

    def self.failure(reason:)
      raise ArgumentError, "unknown Result reason: #{reason.inspect}" unless REASONS.include?(reason)

      new(success: false, reason:)
    end

    def success?
      @success
    end

    def failure?
      !success?
    end

    private

    def initialize(success:, user: nil, strategy: nil, credential: nil, reason: nil)
      @success = success
      @user = user
      @strategy = strategy
      @credential = credential
      @reason = reason
      freeze
    end
  end
end
