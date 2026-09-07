# frozen_string_literal: true

module EmailTokenSupport
  User = Struct.new(:id, :email_address)
  Session = Struct.new(:user_id)
  Token = Struct.new(:user_id, :purpose, :digest, :identifier_digest, :expires_at, :created_at,
    :delivery_payload, :requested_ip_address, :consumed_at, :revoked_at,
    :delivery_lease_key, :delivery_lease_until, :delivered_at, :browser_digest)

  class Cipher
    def initialize
      @payloads = {}
    end

    def encrypt(token:, digest:, expires_at:)
      opaque = SecureRandom.hex(16)
      @payloads[opaque] = [digest, token]
      opaque
    end

    def decrypt(payload:, digest:)
      stored_digest, token = @payloads[payload]
      token if stored_digest == digest
    end
  end

  class Store
    attr_reader :user, :tokens, :sessions

    def initialize
      @user = User.new(1, "person@example.test")
      @tokens, @sessions = [], []
    end

    def with_user(identifier:)
      yield((user.email_address == identifier) ? user : nil)
    end

    def with_token(digest:, current_session: nil)
      token = tokens.find { |item| item.digest == digest }
      snapshot = Marshal.dump([@tokens, @sessions])
      yield(token && user, token)
    rescue
      @tokens, @sessions = Marshal.load(snapshot)
      raise
    end

    def replace_pending(user:, purpose: "sign_in", **attributes)
      tokens.each do |token|
        if token.purpose == purpose && !token.consumed_at && !token.revoked_at
          token.revoked_at = attributes.fetch(:created_at)
          token.delivery_payload = nil
        end
      end
      tokens << Token.new(**attributes, user_id: user.id, purpose: purpose)
    end

    def consume(record:, at:)
      record.consumed_at = at
      record.delivery_payload = nil
    end

    def revoke(record:, at:)
      record.revoked_at = at
      record.delivery_payload = nil
    end

    def lease(record:, key:, until_time:)
      record.delivery_lease_key, record.delivery_lease_until = key, until_time
    end

    def delivered(record:, at:)
      record.delivered_at = at
      record.delivery_payload = record.delivery_lease_key = record.delivery_lease_until = nil
    end

    def finalize_session(user:)
      created = nil
      active = true
      result = yield lambda { |**_attributes|
        raise Latchkey::Error, "session writer is no longer available" unless active && !created
        created = Session.new(user.id)
        sessions << created
        created
      }
      raise Latchkey::Error, "invalid finalizer" unless created && result.equal?(created)
      result
    ensure
      active = false
    end
  end
end
