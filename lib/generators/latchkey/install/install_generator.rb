# frozen_string_literal: true

require "rails/generators"

module Latchkey
  module Generators
    # `bin/rails g latchkey:install` -- see
    # docs/authentication-gem-plan.md section 11 for the full generator
    # surface and section 14 for what v1 actually installs (email links +
    # passkeys + step-up on top of the Rails 8 authentication generator's
    # existing Session, not a parallel session concept).
    #
    # TODO(v1): this generator should assume `bin/rails generate
    # authentication` has already run and:
    #   1. add the migration that extends the generator's own `sessions`
    #      table in place -- authenticated_with, elevated_at, expires_at,
    #      last_seen_at, revoked_at, plus a backfilled token_digest that
    #      replaces the generator's plaintext has_secure_token column
    #      (section 14, "Adopting the generator's Session model" -- this is
    #      the piece to prototype first).
    #   2. add latchkey_credentials and latchkey_sign_in_tokens (section 3).
    #   3. write config/initializers/latchkey.rb (section 9's challenge
    #      config shape).
    #   4. wire the model macro onto the host's User model (section 4).
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      def install
        say "latchkey:install is not implemented yet -- see docs/authentication-gem-plan.md section 11", :yellow
      end
    end
  end
end
