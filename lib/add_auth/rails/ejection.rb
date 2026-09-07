# frozen_string_literal: true

require "json"
require "digest"
require "fileutils"

module AddAuth
  module Rails
    class Ejection
      MANIFEST = "config/add_auth-ejections.json"
      VIEW_GROUPS = {"email_link" => %w[sign_ins], "sessions" => %w[sessions],
                     "step_up" => %w[reauthentications], "passkeys" => %w[passkeys recoveries]}.freeze

      def initialize(host_root:, engine_root: File.expand_path("../../..", __dir__))
        @host, @engine = host_root.to_s, engine_root.to_s
      end

      def files(kind:, only: "all")
        case kind
        when :views
          groups = (only == "all") ? VIEW_GROUPS.keys : only.split(",")
          raise ArgumentError, "unknown view group" unless (groups - VIEW_GROUPS.keys).empty?
          groups.flat_map { |group| VIEW_GROUPS.fetch(group) }.flat_map do |directory|
            glob("app/views/add_auth/#{directory}/**/*.*erb")
          end.concat(glob("app/views/layouts/add_auth/**/*.*erb")).uniq.to_h { |path| [path, path] }
        when :controllers
          glob("app/controllers/add_auth/*_controller.rb").reject { |path| path.end_with?("assets_controller.rb") }.to_h { |path| [path, path] }
        when :javascript
          %w[application codec passkey].to_h do |name|
            ["app/javascript/add_auth/#{name}.js", "lib/generators/add_auth/javascript/templates/#{name}.js"]
          end.merge("app/javascript/add_auth/challenge.js" => "lib/generators/add_auth/email_link/templates/add_auth_challenge.js")
        when :mailer_views
          glob("app/views/add_auth/*_mailer/*.*erb").to_h { |path| [path, path] }
        else
          raise ArgumentError, "unknown ejection kind"
        end
      end

      def install(kind:, only: "all")
        manifest = read_manifest
        results = files(kind: kind, only: only).map do |destination, source|
          body = File.read(File.join(@engine, source))
          generated = decorate(body, destination)
          path = File.join(@host, destination)
          existed = File.exist?(path)
          unless existed
            FileUtils.mkdir_p(File.dirname(path))
            File.write(path, generated)
          end
          # Reruns never advance the baseline of a file already owned by a host.
          manifest[destination] ||= {"version" => AddAuth::VERSION, "source" => source,
                                     "source_hash" => hash(body), "generated_hash" => hash(generated), "baseline" => body}
          {path: destination, preserved: existed}
        end
        path = File.join(@host, MANIFEST)
        FileUtils.mkdir_p(File.dirname(path))
        temporary = "#{path}.#{Process.pid}.tmp"
        File.write(temporary, JSON.pretty_generate({"files" => manifest}) + "\n")
        File.rename(temporary, path)
        results
      ensure
        FileUtils.rm_f(temporary) if temporary
      end

      def report
        inventory = %i[views controllers javascript mailer_views].each_with_object({}) { |kind, all| all.merge!(files(kind: kind)) }
        read_manifest.map do |destination, entry|
          unless inventory[destination] == entry["source"] && entry["baseline"].is_a?(String) && hash(entry["baseline"]) == entry["source_hash"]
            raise AddAuth::Error, "invalid ejection manifest entry"
          end
          source = File.read(File.join(@engine, entry.fetch("source")))
          path = File.join(@host, destination)
          upstream_changed = hash(source) != entry.fetch("source_hash")
          {path: destination, missing: !File.file?(path), customized: File.file?(path) && hash(File.read(path)) != entry["generated_hash"],
           upstream_changed: upstream_changed,
           diff: upstream_changed ? difference(destination, entry.fetch("baseline"), source, entry.fetch("version")) : nil}
        end
      end

      def asset(name)
        destination = "app/javascript/add_auth/#{name}.js"
        source = files(kind: :javascript).fetch(destination)
        host_path = File.join(@host, destination)
        File.file?(host_path) ? host_path : File.join(@engine, source)
      end

      private

      def glob(pattern)
        Dir.glob(File.join(@engine, pattern)).sort.map { |path| path.delete_prefix(@engine + "/") }
      end

      def hash(body) = ::Digest::SHA256.hexdigest(body)

      def decorate(body, path)
        text = "AddAuth ejection: #{AddAuth::VERSION}; source SHA256: #{hash(body)}"
        prefix = if path.end_with?(".erb")
          "<%# #{text} %>"
        elsif path.end_with?(".js")
          "// #{text}"
        else
          "# #{text}"
        end
        "#{prefix}\n#{body}"
      end

      def read_manifest
        path = File.join(@host, MANIFEST)
        return {} unless File.exist?(path)
        raise AddAuth::Error, "ejection manifest is too large" if File.size(path) > 5_000_000
        value = JSON.parse(File.read(path)).fetch("files")
        raise AddAuth::Error, "invalid ejection manifest" unless value.is_a?(Hash) && value.values.all? { |entry| entry.is_a?(Hash) }
        value
      rescue JSON::ParserError, KeyError
        raise AddAuth::Error, "invalid ejection manifest"
      end

      # A valid unified replacement hunk, trimmed to three unchanged context
      # lines at each end. Compare pristine upstream versions, never host secrets.
      def difference(path, before, after, version)
        old, current = before.lines, after.lines
        prefix = 0
        prefix += 1 while prefix < [old.size, current.size].min && old[prefix] == current[prefix]
        suffix = 0
        suffix += 1 while suffix < [old.size, current.size].min - prefix && old[-suffix - 1] == current[-suffix - 1]
        first = [prefix - 3, 0].max
        tail = [suffix - 3, 0].max
        old_part = old[first...(old.size - tail)]
        new_part = current[first...(current.size - tail)]
        old_start = old_part.empty? ? first : first + 1
        new_start = new_part.empty? ? first : first + 1
        header = "--- #{path} (#{version})\n+++ #{path} (#{AddAuth::VERSION})\n"
        header += "@@ -#{old_start},#{old_part.size} +#{new_start},#{new_part.size} @@\n"
        header + old_part.map { |line| "-#{line}" }.join + new_part.map { |line| "+#{line}" }.join
      end
    end
  end
end
