# frozen_string_literal: true

module AddAuth
  module Core
    module Migration
      # A census is evidence for planning, never permission to change authority.
      class Readiness
        MODULES = %w[database_authenticatable registerable recoverable rememberable validatable confirmable lockable trackable omniauthable timeoutable].freeze
        EXTENSIONS = %w[devise-jwt devise_token_auth devise-two-factor devise-security devise-encryptable devise-passkeys devise-webauthn mongoid].freeze
        TARGETS = %w[app/models/user.rb app/models/session.rb app/models/current.rb app/controllers/concerns/authentication.rb].freeze
        ACTIONS = {
          source_version: "Use a separately tested source profile; the initial fixture target is Devise 5.0.4.",
          effective_inventory: "Run the effective inspection in an isolated local copy to verify schema, options and account counts.",
          incomplete_inventory: "Resolve unreadable, oversized, dynamic or truncated input and repeat inspection.",
          unsupported_extension: "Review each extension's credential and policy semantics before conversion.",
          multiple_scopes: "Use an explicitly reviewed identity-scope conversion; do not merge scopes.",
          account_contract: "Prepare additive Rails User/Session/Authentication contracts and review existing files.",
          password_profile: "Prove the effective legacy verifier and a reset route for unsupported credentials.",
          identifier_conflicts: "Resolve missing or normalization-colliding identifiers without merging accounts.",
          policy_mapping: "Map every active account restriction and lifecycle operation before switch.",
          migration_acceptance: "Complete account, lifecycle, provider, client and rollback rehearsals before switching authority."
        }.freeze

        def call(facts)
          codes = [:migration_acceptance]
          codes << :source_version unless facts.dig(:versions, :devise) == "5.0.4"
          codes << :effective_inventory unless facts[:mode] == "effective"
          codes << :incomplete_inventory unless facts[:complete]
          codes << :unsupported_extension if facts.fetch(:extensions, []).any? || facts.fetch(:unknown_modules, 0).positive?
          codes << :multiple_scopes if facts.fetch(:scope_count, 0) > 1
          codes << :account_contract unless facts[:rails_contract]
          codes << :password_profile if facts[:mode] != "effective" || facts.fetch(:accounts, []).any? { |a| a[:custom_verifier] || a[:pepper_configured] || a.dig(:counts, :unknown_password).to_i.positive? }
          codes << :identifier_conflicts if facts.fetch(:accounts, []).any? { |a| a.dig(:counts, :missing_identifier).to_i.positive? || a.dig(:counts, :identifier_collisions).to_i.positive? }
          codes << :policy_mapping if facts.fetch(:modules, []).any? { |name| name != "database_authenticatable" }
          {schema_version: 1, status: "inventory", migration_ready: false,
           facts: facts, blockers: codes.uniq.map { |code| {code: code.to_s, action: ACTIONS.fetch(code)} }}
        end
      end
    end
  end
end
