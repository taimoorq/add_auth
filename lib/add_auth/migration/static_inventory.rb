# frozen_string_literal: true

require "ripper"
require "pathname"
require "add_auth/core/migration/readiness"

module AddAuth
  module Migration
    # Reads a bounded set of source files as data. Never require/load/eval a host.
    class StaticInventory
      MAX_FILES = 2000
      MAX_BYTES = 1_048_576
      TOTAL_BYTES = 16 * 1_048_576
      PATTERNS = %w[app/models/**/*.rb app/controllers/**/*.rb app/services/**/*.rb app/jobs/**/*.rb app/workers/**/*.rb app/mailers/**/*.rb app/helpers/**/*.rb lib/**/*.rb lib/tasks/**/*.rake config/initializers/**/*.rb config/routes.rb db/schema.rb spec/factories/**/*.rb spec/support/**/*.rb].freeze
      SURFACES = {
        devise: %w[Devise devise devise_for devise_scope], warden: %w[warden Warden],
        guards: %w[authenticate_user! current_user user_signed_in? authenticated],
        passwords: %w[encrypted_password password_digest valid_password? password=],
        tokens: %w[authentication_token MobileAuthToken reset_password_token confirmation_token unlock_token],
        providers: %w[OmniAuth omniauth omniauth_callbacks],
        eligibility: %w[active_for_authentication? inactive_message locked_at confirmed_at disabled_at]
      }.freeze

      def initialize(root:)
        @root = File.realpath(root)
      end

      def call
        @complete = true
        @remaining_bytes = TOTAL_BYTES
        paths = PATTERNS.flat_map { |pattern| Dir.glob(File.join(@root, pattern)) }.uniq.sort
        @complete = false if paths.length > MAX_FILES
        sources = paths.first(MAX_FILES).filter_map do |path|
          source = read(path)
          next unless source
          lexical = Ripper.lex(source)
          tokens = lexical.reject { |(_, kind, _, _)| %i[on_comment on_tstring_content].include?(kind) }
          literal_keys = lexical.filter_map { |(_, kind, value, _)| value if kind == :on_tstring_content && SURFACES.values.flatten.include?(value) }
          tree = Ripper.sexp(source)
          @complete = false unless tree
          [relative(path), {tokens: tokens.map { |token| token[2] }, literal_keys: literal_keys, tree: tree}]
        end.to_h
        calls = sources.values.flat_map { |source| devise_calls(source[:tree]) }
        names = calls.flatten
        unknown = names.count { |name| !Core::Migration::Readiness::MODULES.include?(name) }
        @complete = false if names.include?(nil)
        lock = read(File.join(@root, "Gemfile.lock")) || ""
        versions = %w[devise rails ruby bcrypt].to_h do |name|
          version = if name == "ruby"
            lock[/^   ruby (\d+\.\d+\.\d+)/, 1]
          else
            lock[/^    #{Regexp.escape(name)} \((\d+\.\d+(?:\.\d+)*(?:[.a-z0-9-]*))\)/, 1]
          end
          [name.to_sym, version]
        end
        extensions = Core::Migration::Readiness::EXTENSIONS.select { |name| lock.match?(/^    #{Regexp.escape(name)} \(/) }
        targets = Core::Migration::Readiness::TARGETS.select { |path| sources.key?(path) }
        user = sources.dig("app/models/user.rb", :tokens) || []
        facts = {mode: "static", complete: @complete, versions: versions,
                 modules: (names.compact & Core::Migration::Readiness::MODULES).sort,
                 unknown_modules: unknown, extensions: extensions, scope_count: calls.length,
                 rails_contract: targets.length == Core::Migration::Readiness::TARGETS.length && user.include?("has_secure_password") && user.include?("normalizes"),
                 target_conflicts: targets, files_inspected: sources.length,
                 surfaces: SURFACES.transform_values { |terms| sources.filter_map { |path, source| path if ((source[:tokens] + source[:literal_keys]) & terms).any? } }}
        Core::Migration::Readiness.new.call(facts)
      end

      private

      def read(path)
        # Reject symlinks at any depth, even those pointing to another host file.
        current = Pathname.new(path)
        while current.to_s != @root
          return incomplete if current.symlink?
          parent = current.parent
          return incomplete if parent == current
          current = parent
        end
        return incomplete unless File.file?(path)
        return incomplete if @remaining_bytes <= 0
        File.open(path, "rb") do |file|
          limit = [MAX_BYTES, @remaining_bytes].min
          source = file.read(limit + 1)
          @remaining_bytes -= source.bytesize
          return incomplete if source.bytesize > limit
          source.force_encoding(Encoding::UTF_8)
          return incomplete unless source.valid_encoding?
          source
        end
      rescue SystemCallError
        incomplete
      end

      def incomplete
        @complete = false
        nil
      end

      def relative(path) = Pathname.new(path).relative_path_from(Pathname.new(@root)).to_s

      def devise_calls(node)
        return [] unless node.is_a?(Array)
        arguments = if node[0] == :command && node.dig(1, 1) == "devise"
          node[2]
        elsif node[0] == :method_add_arg && node.dig(1, 0) == :fcall && node.dig(1, 1, 1) == "devise"
          node.dig(2, 1)
        end
        if arguments
          args = (arguments[0] == :args_add_block) ? arguments[1] : []
          return [args.reject { |arg| arg[0] == :bare_assoc_hash }.map { |arg| (arg[0] == :symbol_literal) ? arg.dig(1, 1, 1) : nil }]
        end
        node.flat_map { |child| child.is_a?(Array) ? devise_calls(child) : [] }
      end
    end
  end
end
