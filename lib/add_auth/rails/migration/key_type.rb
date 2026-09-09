# frozen_string_literal: true

module AddAuth
  module Rails
    module Migration
      module KeyType
        module_function

        # Resolve when the migration runs, after the host's account table exists.
        # Session IDs remain integer until opaque cursor support is established.
        def for(connection, table, session: false)
          key = connection.primary_key(table)
          column = connection.columns(table).find { |entry| entry.name == key }
          raise ArgumentError, "AddAuth requires a single integer or UUID primary key on #{table}" unless column
          return :bigint if column.type == :integer && column.limit == 8
          return :integer if column.type == :integer
          return :uuid if column.type == :uuid && !session
          raise ArgumentError, session ? "AddAuth requires integer Session IDs; UUID accounts can use integer Sessions" : "AddAuth requires an integer or UUID account primary key"
        end
      end
    end
  end
end
