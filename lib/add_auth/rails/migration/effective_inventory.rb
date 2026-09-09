# frozen_string_literal: true

require "add_auth/core/migration/readiness"

module AddAuth
  module Rails
    module Migration
      class EffectiveInventory
        LIMIT = 10_000
        ACCOUNT_FIELDS = %w[email email_address encrypted_password password_digest confirmed_at unconfirmed_email locked_at failed_attempts disabled_at deleted_at remember_created_at reset_password_token confirmation_token unlock_token authentication_token provider uid].freeze
        OPTIONS = %i[authentication_keys case_insensitive_keys strip_whitespace_keys stretches password_length reconfirmable allow_unconfirmed_access_for confirm_within reset_password_within maximum_attempts unlock_strategy unlock_in remember_for sign_in_after_reset_password].freeze

        def initialize(limit: LIMIT)
          raise ArgumentError, "limit must be between 1 and 100000" unless limit.is_a?(Integer) && limit.between?(1, 100_000)
          @limit = limit
        end

        def call
          unless %w[test development].include?(::Rails.env.to_s) && defined?(::Devise)
            raise ArgumentError, "effective preflight requires a local test/development Devise host"
          end
          @complete = true
          mappings = ::Devise.mappings.values
          models = mappings.map(&:to).uniq
          connections = models.map(&:connection_pool).uniq
          raise ArgumentError, "inspect one Active Record connection pool at a time" unless connections.length == 1
          accounts = read_only(connections.first) { models.map { |model| account(model) } }
          all_modules = accounts.flat_map { |entry| entry[:modules] }.uniq
          facts = {mode: "effective", complete: @complete, row_limit: @limit,
                   versions: %w[devise rails bcrypt].to_h { |name| [name.to_sym, Gem.loaded_specs[name]&.version&.to_s] }.merge(ruby: RUBY_VERSION),
                   scope_count: mappings.length, modules: all_modules & Core::Migration::Readiness::MODULES,
                   unknown_modules: accounts.sum { |entry| entry[:unknown_modules] },
                   extensions: Core::Migration::Readiness::EXTENSIONS.select { |name| Gem.loaded_specs.key?(name) },
                   rails_contract: accounts.length == 1 && accounts.first[:rails_contract], accounts: accounts}
          Core::Migration::Readiness.new.call(facts)
        end

        private

        def read_only(pool)
          pool.with_connection do |connection|
            raise ArgumentError, "effective preflight requires its own transaction" if connection.transaction_open?
            case connection.adapter_name
            when "PostgreSQL"
              connection.transaction(requires_new: true) do
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                connection.execute("SET LOCAL statement_timeout = '10s'")
                yield
              end
            when "SQLite"
              previous = connection.select_value("PRAGMA query_only").to_i
              begin
                connection.execute("PRAGMA query_only = ON")
                # Rails 8.1 starts ordinary SQLite transactions with BEGIN
                # IMMEDIATE, which requests write authority even for SELECTs.
                connection.execute("BEGIN DEFERRED TRANSACTION")
                begin
                  yield
                ensure
                  connection.execute("ROLLBACK")
                end
              ensure
                connection.execute("PRAGMA query_only = #{previous}")
              end
            else
              raise ArgumentError, "effective preflight supports SQLite and PostgreSQL only"
            end
          end
        end

        def account(model)
          columns = model.columns_hash
          fields = ACCOUNT_FIELDS & columns.keys
          # No model instances, callbacks, password verification or normalization hooks.
          rows = model.unscoped.limit(@limit + 1).pluck(*fields).map { |values| fields.zip(Array(values)).to_h }
          @complete = false if rows.length > @limit
          rows = rows.first(@limit)
          modules = model.devise_modules.map(&:to_s)
          lookup_keys = Array(model.authentication_keys)
          identifier = (lookup_keys.length == 1 && fields.include?(lookup_keys.first.to_s)) ? lookup_keys.first.to_s : "email"
          @complete = false unless lookup_keys == [:email] || lookup_keys == [:email_address]
          password = fields.include?("encrypted_password") ? "encrypted_password" : "password_digest"
          keys = rows.map { |row| row[identifier].to_s.strip.downcase }
          nonblank = keys.reject(&:empty?)
          options = OPTIONS.filter_map { |name| [name, safe_option(model.public_send(name))] if model.respond_to?(name) }.to_h
          verifier = model.instance_method(:valid_password?).source_location&.first
          devise_root = Gem.loaded_specs.fetch("devise").full_gem_path + "/"
          indexes = model.connection.indexes(model.table_name)
          {model: safe_name(model.name), table: safe_name(model.table_name),
           primary_key_type: columns[model.primary_key]&.type&.to_s,
           database: model.connection.adapter_name, identifier: identifier,
           identifier_type: columns[identifier]&.type&.to_s,
           identifier_collation: columns[identifier]&.respond_to?(:collation) ? safe_name(columns[identifier].collation) : nil,
           unique_identifier_index: indexes.any? { |index| index.unique && index.columns == [identifier] && !index.where },
           modules: modules & Core::Migration::Readiness::MODULES,
           unknown_modules: (modules - Core::Migration::Readiness::MODULES).length,
           options: options, pepper_configured: model.respond_to?(:pepper) && !model.pepper.to_s.empty?,
           custom_verifier: !verifier&.start_with?(devise_root) || !model.instance_method(:password=).source_location&.first&.start_with?(devise_root),
           rails_contract: (model.name == "User" && fields.include?("email_address") && fields.include?("password_digest") && model.respond_to?(:authenticate_by) && defined?(::Session) && defined?(::Authentication)) ? true : false,
           related_tables: related_tables(model),
           counts: {inspected: rows.length, missing_identifier: keys.count(&:empty?), identifier_collisions: nonblank.length - nonblank.uniq.length,
                    unknown_password: rows.count { |row| !row[password].to_s.match?(/\A\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{53}\z/) },
                    unconfirmed: fields.include?("confirmed_at") ? rows.count { |row| row["confirmed_at"].nil? } : 0,
                    reconfirming: rows.count { |row| !row["unconfirmed_email"].to_s.empty? },
                    locked: rows.count { |row| row["locked_at"] }, disabled: rows.count { |row| row["disabled_at"] },
                    deleted: rows.count { |row| row["deleted_at"] },
                    outstanding_authority: rows.count { |row| %w[remember_created_at reset_password_token confirmation_token unlock_token authentication_token].any? { |key| !row[key].to_s.empty? } }}}
        end

        def related_tables(model)
          connection = model.connection
          tables = connection.tables.sort
          @complete = false if tables.length > 200
          tables.first(200).filter_map do |table|
            next if table == model.table_name
            columns = connection.columns(table).to_h { |column| [column.name, column] }
            foreign_keys = connection.foreign_keys(table).select { |key| key.to_table == model.table_name }
            reference = foreign_keys.first&.column || ("user_id" if model.name == "User" && columns.key?("user_id"))
            next unless reference && columns.key?(reference)
            quoted_table = connection.quote_table_name(table)
            quote = ->(name) { connection.quote_column_name(name) }
            identity_fields = %w[provider issuer subject uid] & columns.keys
            selected = [reference, *identity_fields]
            records = connection.select_rows("SELECT #{selected.map { |field| quote.call(field) }.join(", ")} FROM #{quoted_table} LIMIT #{@limit + 1}")
            @complete = false if records.length > @limit
            records = records.first(@limit)
            identities = identity_fields.empty? ? [] : records.map { |row| row.drop(1) }
            account_table = connection.quote_table_name(model.table_name)
            key = quote.call(model.primary_key)
            reference_column = quote.call(reference)
            orphan_count = connection.select_value(<<~SQL).to_i
              SELECT COUNT(*) FROM
                (SELECT #{reference_column} FROM #{quoted_table} LIMIT #{@limit + 1}) source
              LEFT JOIN #{account_table} account ON account.#{key} = source.#{reference_column}
              WHERE source.#{reference_column} IS NOT NULL AND account.#{key} IS NULL
            SQL
            {table: safe_name(table), reference: safe_name(reference), key_type: columns[reference].type.to_s,
             foreign_key_enforced: foreign_keys.any?, inspected: records.length,
             orphaned_references: orphan_count, duplicate_identities: identities.length - identities.uniq.length}
          end
        end

        def safe_name(value)
          value.to_s.match?(/\A[A-Za-z_]\w*(?:::\w+)*\z/) ? value.to_s : nil
        end

        def safe_option(value)
          case value
          when nil, true, false, Numeric then value
          when Symbol then safe_name(value)
          when Range then [safe_option(value.begin), safe_option(value.end), value.exclude_end?]
          when Array then value.map { |item| safe_option(item) }
          when Hash then value.to_h { |key, item| [safe_name(key), safe_option(item)] }
          else
            # ActiveSupport::Duration exposes only a numeric duration.
            value.is_a?(ActiveSupport::Duration) ? value.to_i : "custom"
          end
        end
      end
    end
  end
end
