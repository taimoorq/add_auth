# frozen_string_literal: true

module PasskeyStoreSupport
  User = Struct.new(:id, :email_address, :password_digest, :webauthn_id, :latchkey_strict, :latchkey_policy_version)
  Session = Struct.new(:id, :user_id, :token_digest, :authenticated_with, :authenticated_at, :expires_at, :last_seen_at,
    :revoked_at, :created_at, :elevated_at, :elevated_with, :elevation_purpose, :elevation_credential_id, :elevation_uv,
    :elevation_version, :elevation_expires_at, :authentication_policy_version, :authentication_credential_id, :authentication_uv)
  Credential = Struct.new(:id, :user_id, :external_id, :public_key, :sign_count, :nickname, :aaguid, :transports,
    :backup_eligible, :backup_state, :last_used_at, :revoked_at, :created_at)
  Ceremony = Struct.new(:id, :digest, :challenge, :kind, :browser_digest, :configuration_digest, :user_id,
    :session_id, :session_digest, :authentication_purpose, :expires_at, :consumed_at, :created_at)

  # Copy-on-read models a store snapshot, so a stale caller cannot silently
  # inherit a rotated bearer just because the fake shares object references.
  class Store
    def initialize
      @tables = {User => [User.new(id: 1, email_address: "fake@example.test", password_digest: "hashed", latchkey_strict: false, latchkey_policy_version: 0)], Session => [], Credential => [], Ceremony => []}
    end

    def user = copy(@tables[User].first)

    def copy(value)
      case value
      when Struct then value.class.new(**value.to_h.transform_values { |item| copy(item) })
      when Hash then value.transform_values { |item| copy(item) }
      when Array then value.map { |item| copy(item) }
      when String then String.new(value)
      else value
      end
    end

    def transaction
      before = copy(@tables)
      yield
    rescue
      @tables = before
      raise
    end

    def with_user(id:, replacing: nil)
      transaction { yield((id == user.id) ? user : nil) }
    end

    def with_session(id: nil, digest: nil)
      transaction do
        row = @tables[Session].find { |item| digest ? item.token_digest == digest : item.id == id }
        yield(row && user, copy(row))
      end
    end

    def find_for_user_in_transaction(user_id:, session_id:)
      copy(@tables[Session].find { |row| row.id == session_id && row.user_id == user_id })
    end

    def update(row, **attributes)
      stored = @tables.fetch(row.class).find { |item| item.id == row.id }
      attributes.each { |key, value| row[key] = stored[key] = value }
      true
    end

    def insert(type, **attributes)
      rows = @tables.fetch(type)
      row = type.new(**attributes, id: rows.size + 1, created_at: Time.now)
      rows << copy(row)
      row
    end

    def create(user:, **attributes) = insert(Session, user_id: user.id, **attributes)
    def create_ceremony(**attributes) = insert(Ceremony, **attributes)
    def credentials(user:) = copy(@tables[Credential].select { |row| row.user_id == user.id && !row.revoked_at })
    def credential(id:) = copy(@tables[Credential].find { |row| row.external_id == id })

    def create_credential(user:, **attributes)
      insert(Credential, user_id: user.id, **attributes) unless credential(id: attributes[:external_id])
    end

    def with_ceremony(digest:, user_id:, replacing: nil)
      transaction do
        yield((user_id == user.id) ? user : nil, copy(@tables[Ceremony].find { |row| row.digest == digest }))
      end
    end
  end
end
