# frozen_string_literal: true

require "latchkey/rails/stores/account_lock"
require "latchkey/rails/stores/delivery_state"

module Latchkey
  module Rails
    module Stores
      # Lock the account before reading token state, serializing issuance,
      # consumption and revocation. All injected models must share a pool.
      # Host finalizers may perform DB writes only, on this same connection.
      class EmailTokens
        include DeliveryState

        def initialize(user_model:, token_model:, session_model:, identifier: :email_address)
          @users, @tokens, @sessions = user_model, token_model, session_model
          unless [@tokens, @sessions].all? { |model| model.connection_pool.equal?(@users.connection_pool) }
            raise ArgumentError, "authentication models must share one connection pool"
          end
          unless @users.column_names.include?(identifier.to_s)
            raise ArgumentError, "unknown identifier column"
          end
          @identifier = identifier
        end

        def with_user(identifier:)
          with_account(@users.find_by(@identifier => identifier)) { |user| yield user }
        end

        def with_token(digest:, current_session: nil)
          raise ArgumentError, "digest must be a nonempty string" unless digest.is_a?(String) && !digest.empty?

          # A request may have inspected this token before another connection
          # consumed it. Never authorize from Active Record's query cache.
          @tokens.uncached do
            locator = @tokens.find_by(digest: digest)
            with_account(locator && @users.find_by(@users.primary_key => locator.user_id), additional_id: current_session&.user_id) do |user|
              yield user, user && @tokens.find_by(digest: digest, user_id: user.id)
            end
          end
        end

        def replace_pending(user:, purpose: "sign_in", **attributes)
          scope = attributes.slice(:session_id, :authentication_purpose)
          @tokens.where(user_id: user.id, purpose: purpose, consumed_at: nil, revoked_at: nil, **scope)
            .update_all(revoked_at: attributes.fetch(:created_at), delivery_payload: nil)
          @tokens.create!(**attributes, user_id: user.id, purpose: purpose)
        end

        def session_for(user:, id:)
          @sessions.uncached { @sessions.find_by(id: id, user_id: user.id) }
        end

        def consume(record:, at:)
          record.update!(consumed_at: at, delivery_payload: nil)
        end

        # This capability owns creation; a model's previously_new_record? flag
        # cannot establish which transaction created it. The writer expires when
        # the callback exits and may create exactly one session for this account.
        def finalize_session(user:)
          transaction = @users.current_transaction
          created = nil
          active = true
          writer = lambda do |**attributes|
            unless active && transaction.open? && @users.current_transaction.equal?(transaction) && !created
              raise Latchkey::Error, "session writer is no longer available"
            end
            created = @sessions.create!(**attributes.except(:user_id), user_id: user.id)
          end
          result = yield writer
          unless created && result.equal?(created) && created.persisted? && created.user_id == user.id
            raise Latchkey::Error, "finalizer must persist a session using the transaction writer"
          end
          result
        ensure
          active = false
        end

        def refresh_session(session) = session.reload

        def issued?(request_id:) = @tokens.exists?(request_id: request_id)

        private

        def with_account(user, additional_id: nil)
          AccountLock.new(@users).call(id: user&.id, additional_id: additional_id) { |account| yield account }
        end
      end
    end
  end
end
