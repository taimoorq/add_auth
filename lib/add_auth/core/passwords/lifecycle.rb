# frozen_string_literal: true

module AddAuth
  module Core
    module Passwords
      # Called only inside the owning account transaction. The adapter supplies
      # Rails hashing and persistence; these decisions are shared by entry paths.
      class Lifecycle
        def initialize(store:, policy:, enabled:, maximum_attempts: 20, unlock_in: 3600, clock: Time, issue_unlock: ->(_user) {})
          unless maximum_attempts.is_a?(Integer) && maximum_attempts.between?(1, 100) &&
              unlock_in.is_a?(Numeric) && unlock_in.finite? && unlock_in.between?(60, 86_400)
            raise ArgumentError, "configure bounded password attempts and unlock duration"
          end
          @store, @policy, @enabled, @maximum, @unlock_in, @clock, @issue_unlock = store, policy, enabled, maximum_attempts, unlock_in, clock, issue_unlock
        end

        def prepare(user:)
          return unless @enabled && user && !user.add_auth_manual_lock && user.locked_at &&
            user.add_auth_locked_until && user.add_auth_locked_until <= @clock.now
          @store.update_account(user: user, locked_at: nil, add_auth_locked_until: nil, failed_attempts: 0)
        end

        def verified(user:, password:, valid:, rehash: true)
          return false unless user && @policy.call(user) == true
          if valid
            @store.update_account(user: user, failed_attempts: 0) if @enabled && user.failed_attempts != 0
            if rehash && user.respond_to?(:add_auth_password_scheme) && user.add_auth_password_scheme == "devise_bcrypt" && assignable?(password)
              @store.rehash_password(user: user, password: password)
              @store.revoke_authority(user: user, at: @clock.now)
            end
            true
          else
            record_failure(user) if @enabled
            false
          end
        end

        private

        def assignable?(password)
          password.is_a?(String) && password.valid_encoding? && password.bytesize.between?(1, 72) && !password.include?("\0")
        end

        def record_failure(user)
          attempts = [user.failed_attempts.to_i + 1, @maximum].min
          changes = {failed_attempts: attempts}
          if attempts >= @maximum
            changes[:locked_at] = @clock.now
            changes[:add_auth_locked_until] = @clock.now + @unlock_in
          end
          @store.update_account(user: user, **changes)
          if attempts >= @maximum
            @store.revoke_authority(user: user, at: @clock.now)
            @issue_unlock.call(user)
          end
        end
      end
    end
  end
end
