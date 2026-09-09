# frozen_string_literal: true

require "digest"
require "add_auth/core/passwords/legacy_bcrypt"

module AddAuth
  module Core
    module Migration
      class AccountAdoption
        # A retired source may still save harmless profile/tracking fields, but
        # every credential, lifecycle flag and outstanding Devise proof remains
        # owned by its selected authority. The bridge supplies dirty field names;
        # only Core classifies their security meaning.
        SOURCE_AUTHORITY_FIELDS = %w[email encrypted_password email_address password_digest confirmed_at unconfirmed_email
          confirmation_token confirmation_sent_at reset_password_token reset_password_sent_at
          locked_at failed_attempts unlock_token remember_created_at
          add_auth_locked_until add_auth_manual_lock add_auth_password_scheme add_auth_migration_stamp
          add_auth_strict add_auth_policy_version webauthn_id disabled_at deleted_at].freeze

        def initialize(store:)
          @store = store
        end

        def call(after: nil, limit: 100)
          raise ArgumentError, "batch size must be between 1 and 1000" unless limit.is_a?(Integer) && limit.between?(1, 1000)
          page = @store.source_page(after: after, limit: limit + 1)
          counts = {inspected: 0, prepared: 0, unchanged: 0, conflicts: 0, changed_source: 0, active_destination: 0}
          page.first(limit).each do |snapshot|
            counts[:inspected] += 1
            outcome = @store.with_account(snapshot.fetch(:id)) do |source|
              next :changed_source unless source && stamp(source) == stamp(snapshot)
              next :active_destination unless source[:authority] == "devise"
              attributes = self.class.projection(email: source[:email], encrypted_password: source[:encrypted_password])
              next :conflicts unless attributes
              next :unchanged if source[:migration_stamp] == attributes[:add_auth_migration_stamp] && source[:email_address] == attributes[:email_address] && source[:password_digest] == attributes[:password_digest] && source[:scheme] == "devise_bcrypt"
              @store.prepare(id: source[:id], **attributes)
              :prepared
            end
            counts[outcome || :conflicts] += 1
          end
          counts.merge(next_cursor: (page.length > limit) ? page[limit - 1][:id] : nil)
        end

        def self.stamp(email:, encrypted_password:)
          values = [email, encrypted_password].map { |value| value.nil? ? "nil:" : "#{value.bytesize}:#{value}" }
          ::Digest::SHA256.hexdigest(values.join("|"))
        end

        def self.source_authority?(value) = value == "devise"

        def self.authorize_source_write!(authority:, changed_fields:, authority_changed: false)
          raise AddAuth::Error, "switch account authority through the reviewed migration procedure" if authority_changed
          return if source_authority?(authority)
          return if authority == "add_auth" && (changed_fields.map(&:to_s) & SOURCE_AUTHORITY_FIELDS).empty?
          raise AddAuth::Error, "source authentication state is no longer authoritative"
        end

        def self.projection_for_write(authority:, authority_changed:, changed_fields:, **source)
          authorize_source_write!(authority: authority, authority_changed: authority_changed, changed_fields: changed_fields)
          source_authority?(authority) ? projection(**source) || raise(AddAuth::Error, "unsupported source credential profile; reconcile before writing") : {}
        end

        def self.projection(email:, encrypted_password:)
          return unless email.is_a?(String) && email.valid_encoding? && email.bytesize.between?(1, 254)
          identifier = email.strip.downcase
          return unless identifier.match?(/\A[^\s@]+@[^\s@]+\z/) && identifier.bytesize <= 254
          match = encrypted_password.is_a?(String) && Passwords::LegacyBcrypt::PATTERN.match(encrypted_password)
          return unless match && match[1].to_i.between?(4, 14)
          {email_address: identifier, password_digest: encrypted_password, add_auth_password_scheme: "devise_bcrypt",
           add_auth_migration_stamp: stamp(email: email, encrypted_password: encrypted_password)}
        end

        private

        def stamp(source) = self.class.stamp(email: source[:email], encrypted_password: source[:encrypted_password])
      end
    end
  end
end
