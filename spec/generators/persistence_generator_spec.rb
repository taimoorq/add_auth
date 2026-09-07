# frozen_string_literal: true

require "rails_helper"
require "tmpdir"
require "open3"
require "rbconfig"
require "rubygems/package"
require "rubygems/installer"

RSpec.describe "Persistence generator in a fresh Rails host" do
  it "generates, migrates and boots a real host without replacing sessions or custom models" do
    Dir.mktmpdir("latchkey-host-") do |parent|
      host = File.join(parent, "host")
      bundle = File.expand_path(ENV.fetch("BUNDLE_GEMFILE", File.expand_path("../../Gemfile", __dir__)))
      development_lockfile = Bundler.default_lockfile
      development_lock = File.binread(development_lockfile)
      environment = {"BUNDLE_GEMFILE" => bundle, "RAILS_ENV" => "test", "SECRET_KEY_BASE_DUMMY" => "1"}
      ruby = RbConfig.ruby
      stdout, stderr, status = Open3.capture3(environment, ruby, Gem.bin_path("railties", "rails"),
        "new", host, "--skip-test", "--skip-asset-pipeline", "--skip-bundle", "--skip-git",
        "--skip-hotwire", "--skip-javascript", "--skip-jbuilder", "--skip-bootsnap")
      expect(status.success?).to be(true), stdout + stderr
      run = ->(*args) do
        output, errors, result = Open3.capture3(environment, ruby, "bin/rails", *args, chdir: host)
        expect(result.success?).to be(true), output + errors
        output
      end
      artifact = File.join(parent, "latchkey.gem")
      gemspec = Gem::Specification.load(File.expand_path("../../latchkey.gemspec", __dir__))
      Gem::Package.build(gemspec, false, false, artifact)
      installed = Gem::Installer.at(artifact, install_dir: File.join(parent, "gems"), ignore_dependencies: true, wrappers: false).install
      # Bundler's path source needs the installed gem's serialized specification;
      # runtime files above came exclusively from the built gem archive.
      File.write(File.join(installed.full_gem_path, "latchkey.gemspec"), installed.to_ruby)
      # Give the scratch host its own Gemfile and lockfile, including Bundler's
      # original environment used by Rails' `bundle add bcrypt` subprocess.
      host_bundle = File.join(host, "Gemfile")
      File.write(host_bundle, %(source "https://rubygems.org"\ngem "latchkey", path: #{installed.full_gem_path.inspect}\ngem "rails", "=#{Rails.version}"\ngem "sqlite3", ">= 2.1"\ngem "puma"\n))
      environment["BUNDLE_GEMFILE"] = host_bundle
      environment["BUNDLER_ORIG_BUNDLE_GEMFILE"] = host_bundle
      environment["BUNDLE_LOCKFILE"] = "#{host_bundle}.lock"
      environment["BUNDLER_ORIG_BUNDLE_LOCKFILE"] = "#{host_bundle}.lock"
      output, errors, result = Open3.capture3(environment, ruby, Gem.bin_path("bundler", "bundle"), "install", "--local", chdir: host)
      expect(result.success?).to be(true), output + errors
      run.call("generate", "authentication")
      expect(File.binread(development_lockfile)).to eq(development_lock)
      # Exercise session-only adoption before any email model or table exists,
      # then restore the host files to retain the persistence-only checks below.
      session_only_paths = %w[app/models/user.rb app/models/session.rb app/controllers/application_controller.rb config/routes.rb]
      originals = session_only_paths.to_h { |path| [path, File.binread(File.join(host, path))] }
      run.call("generate", "latchkey:session_upgrade")
      run.call("db:prepare")
      result = run.call("runner", <<~RUBY)
        abort "email model unexpectedly installed" if defined?(LatchkeySignInToken)
        user = User.create!(email_address: "session-only@example.test", password: "correct-password")
        initial = Latchkey::Rails::Runtime.sessions.start(user: user, method: :password)
        user.update!(password: "replacement-password")
        abort "session-only password change failed" unless user.authenticate("replacement-password")
        abort "session-only session not revoked" unless initial.session.reload.revoked_at
        puts "session-only lifecycle verified"
      RUBY
      expect(result).to include("session-only lifecycle verified")
      # This is an isolated generated host, never the developer's database.
      run.call("db:drop")
      FileUtils.rm_f(File.join(host, "db/schema.rb"))
      originals.each { |path, content| File.binwrite(File.join(host, path), content) }
      FileUtils.rm(File.join(host, "config/initializers/latchkey.rb"))
      Dir[File.join(host, "db/migrate/*_{extend_sessions_for_latchkey,add_latchkey_elevation}.rb")].each { |path| FileUtils.rm(path) }
      session_source = File.read(File.join(host, "app/models/session.rb"))
      run.call("generate", "latchkey:email_tokens")
      migrations = Dir[File.join(host, "db/migrate/*_create_latchkey_sign_in_tokens.rb")]
      expect(migrations.size).to eq(1)
      model = File.join(host, "app/models/latchkey_sign_in_token.rb")
      File.open(model, "a") { |file| file.puts "# host customization" }
      run.call("generate", "latchkey:email_tokens")
      expect(Dir[File.join(host, "db/migrate/*_create_latchkey_sign_in_tokens.rb")]).to eq(migrations)
      expect(File.read(model)).to include("host customization")
      expect(File.read(File.join(host, "app/models/session.rb"))).to eq(session_source)
      run.call("db:prepare")
      result = run.call("runner", <<~RUBY)
        abort "unexpected session token column" if Session.column_names.include?("token")
        abort "unexpected session digest column" if Session.column_names.include?("token_digest")
        user = User.create!(email_address: "host@example.test", password: "correct-password")
        user.sessions.create!
        abort "incorrect session model" unless Session.count == 1
        abort "missing token table" unless LatchkeySignInToken.table_exists?
        client = ActionDispatch::Integration::Session.new(Rails.application)
        client.get "/session/new"
        abort "host sign-in does not render" unless client.response.status == 200
        puts "host verified"
      RUBY
      expect(result).to include("host verified")
      run.call("generate", "latchkey:install")
      initializer = File.join(host, "config/initializers/latchkey.rb")
      initial = File.read(initializer)
      run.call("generate", "latchkey:install")
      expect(File.read(initializer)).to eq(initial)
      expect(Dir[File.join(host, "db/migrate/*_extend_sessions_for_latchkey.rb")]).to be_empty
      controller_path = File.join(host, "app/controllers/sessions_controller.rb")
      original_controller = File.read(controller_path)
      run.call("generate", "latchkey:session_upgrade")
      run.call("generate", "latchkey:session_upgrade")
      File.open(initializer, "a") { |file| file.puts "Latchkey.configuration.rate_limit_store = ActiveSupport::Cache::MemoryStore.new" }
      run.call("db:migrate")
      expect(File.read(controller_path)).to eq(original_controller)
      result = run.call("runner", <<~RUBY)
        client = ActionDispatch::Integration::Session.new(Rails.application)
        %w[/sign-in /latchkey.css /latchkey/boot.js /latchkey/turbo.js /latchkey/stimulus.js /latchkey/challenge.js].each do |path|
          client.get path
          abort "session-only asset missing: \#{path}" unless client.response.status == 200
        end
        client.post "/session", params: {email_address: "host@example.test", password: "correct-password"}
        abort "session-only sign-in failed" unless client.response.status == 303
        client.post "/sessions/revoke-all", params: {password: "correct-password"}
        abort "session-only revoke-all failed" unless client.response.status == 303
        client.follow_redirect!
        abort "session-only sign-in destination missing" unless client.response.status == 200
        abort "disabled email form shown" if client.response.body.include?("Send sign-in link")
        client.post "/sign-in/email", params: {email_address: "host@example.test"}
        abort "disabled email route available" unless client.response.status == 404
        puts "session-only host verified"
      RUBY
      expect(result).to include("session-only host verified")
      run.call("generate", "latchkey:email_link")
      run.call("generate", "latchkey:email_link")
      expect(Dir[File.join(host, "db/migrate/*_extend_sessions_for_latchkey.rb")].size).to eq(1)
      expect(File.read(File.join(host, "config/routes.rb")).scan("# Latchkey sign-in").size).to eq(1)
      File.open(initializer, "a") do |file|
        file.puts <<~RUBY
          Latchkey.configure do |config|
            config.base_url = "http://example.test"
            config.mail_from = "signin@example.test"
            config.rate_limit_store = ActiveSupport::Cache::MemoryStore.new
          end
        RUBY
      end
      run.call("db:migrate")
      run.call("generate", "latchkey:views")
      view = File.join(host, "app/views/latchkey/sign_ins/_form.html.erb")
      File.open(view, "a") { |file| file.puts "<!-- host view customization -->" }
      run.call("generate", "latchkey:views")
      expect(File.read(view)).to include("host view customization")
      run.call("generate", "latchkey:views", "--only=sessions")
      session_view = File.join(host, "app/views/latchkey/sessions/index.html.erb")
      expect(File).to exist(session_view)
      File.open(session_view, "a") { |file| file.puts "<!-- host session view customization -->" }
      run.call("generate", "latchkey:views", "--only=sessions")
      expect(File.read(session_view)).to include("host session view customization")
      result = run.call("runner", <<~RUBY)
        user = User.find_by!(email_address: "host@example.test")
        abort "missing session digest" unless Session.column_names.include?("token_digest")
        abort "legacy rows modified" unless user.sessions.first.token_digest.nil?
        client = ActionDispatch::Integration::Session.new(Rails.application)
        client.get "/sign-in"
        abort "public sign-in does not render" unless client.response.status == 200
        abort "ejected view not used" unless client.response.body.include?("host view customization")
        ActiveJob::Base.queue_adapter = :inline
        ActionMailer::Base.delivery_method = :test
        client.post "/sign-in/email", params: {email_address: user.email_address}
        abort "email request failed" unless client.response.status == 303
        mail = ActionMailer::Base.deliveries.last
        abort "missing mail" unless mail
        link = URI.parse(mail.body.decoded[/http[^\\s]+/])
        client.get link.request_uri
        abort "confirmation failed" unless client.response.body.include?("Confirm your sign-in")
        token = URI.decode_www_form(link.query).to_h.fetch("token")
        client.post "/sign-in/link", params: {token: token, switch_account: "1"}
        abort "sign-in failed" unless client.response.status == 303 && Session.last.authenticated_with == "email_link"
        Latchkey.configuration.email_link.same_browser = true
        client.post "/sign-in/email", params: {email_address: user.email_address}
        bound_link = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\\s]+/])
        outsider = ActionDispatch::Integration::Session.new(Rails.application)
        outsider.get bound_link.request_uri
        abort "ejected browser binding missing" unless outsider.response.body.include?("Open this link in the requesting browser")
        bound_token = URI.decode_www_form(bound_link.query).to_h.fetch("token")
        outsider.post "/sign-in/link", params: {token: bound_token, switch_account: "1"}
        abort "wrong browser accepted" unless outsider.response.status == 422
        client.post "/sign-in/link", params: {token: bound_token, switch_account: "1"}
        abort "bound email sign-in failed" unless client.response.status == 303
        Latchkey.configuration.email_link.same_browser = false
        puts "public host verified"
      RUBY
      expect(result).to include("public host verified")
      run.call("generate", "latchkey:step_up")
      run.call("generate", "latchkey:step_up")
      expect(Dir[File.join(host, "db/migrate/*_add_latchkey_reauthentication.rb")].size).to eq(1)
      run.call("db:migrate")
      run.call("generate", "latchkey:views", "--only=step_up")
      result = run.call("runner", <<~RUBY)
        Latchkey.configuration.step_up.purposes = {manage_profile: {methods: [:password, :email_link], return_to: "/sessions"}}
        client = ActionDispatch::Integration::Session.new(Rails.application)
        client.post "/sign-in/password", params: {email_address: "host@example.test", password: "correct-password"}
        row = Session.last
        old_digest = row.token_digest
        client.get "/reauthenticate?purpose=manage_profile"
        abort "reauthentication page missing" unless client.response.body.include?("Verify with password")
        client.post "/reauthenticate/password", params: {purpose: "manage_profile", password: "correct-password"}
        abort "password elevation failed" unless client.response.status == 303 && row.reload.elevated_with == "password" && row.token_digest != old_digest
        ActiveJob::Base.queue_adapter = :inline
        ActionMailer::Base.delivery_method = :test
        client.post "/reauthenticate/email", params: {purpose: "manage_profile"}
        link = URI.parse(ActionMailer::Base.deliveries.last.body.decoded[/http[^\\s]+/])
        client.get link.request_uri
        abort "email reauthentication confirmation missing" unless client.response.body.include?("Confirm this verification")
        token = URI.decode_www_form(link.query).to_h.fetch("token")
        client.post "/reauthenticate/link", params: {token: token}
        abort "email elevation failed" unless client.response.status == 303 && row.reload.elevated_with == "email_link"
        verified = Latchkey::Rails::Runtime.sessions.with_elevation(user: row.user, session: row, purpose: :manage_profile,
          policy: Latchkey::Rails::Runtime.step_up_policy) { |account| account.update!(updated_at: Time.current) }
        abort "host mutation guard failed" unless verified.success?
        puts "ejected reauthentication verified"
      RUBY
      expect(result).to include("ejected reauthentication verified")
      run.call("generate", "latchkey:passkeys")
      run.call("generate", "latchkey:passkeys")
      expect(Dir[File.join(host, "db/migrate/*_add_latchkey_passkeys.rb")].size).to eq(1)
      expect(Dir[File.join(host, "db/migrate/*_create_latchkey_security_events.rb")].size).to eq(1)
      run.call("db:migrate")
      journey = File.read(File.expand_path("../support/generated_passkey_journey.rb", __dir__))
      expect(run.call("runner", journey)).to include("packaged passkey recovery verified")
      %w[views controllers javascript mailer_views].each do |kind|
        run.call("generate", "latchkey:#{kind}")
        run.call("generate", "latchkey:#{kind}")
      end
      expect(run.call("runner", journey)).to include("packaged passkey recovery verified")
      # The README session/email-only trial intentionally uses its own feature set.
      File.open(initializer, "a") { |file| file.puts "Latchkey.configuration.passkeys.enabled = false" }
      # Execute the literal local configuration snippets shipped in the README.
      readme = File.read(File.expand_path("../../README.md", __dir__))
      snippets = readme.scan(/```ruby\n(.*?)```/m).flatten.map { |block| block.gsub(/^   /, "") }
      trial_initializer = snippets.find { |block| block.include?('config.base_url = "http://localhost:3000"') }
      trial_environment = snippets.find { |block| block.include?("config.action_mailer.file_settings") }
      expect(trial_initializer).to be_present
      expect(trial_environment).to be_present
      File.open(initializer, "a") { |file| file.puts trial_initializer }
      File.open(File.join(host, "config/environments/test.rb"), "a") do |file|
        file.puts "Rails.application.configure do\n#{trial_environment}\nend"
      end
      result = run.call("runner", <<~RUBY)
        client = ActionDispatch::Integration::Session.new(Rails.application)
        client.post "/sign-in/email", params: {email_address: "host@example.test"}
        abort "README request failed" unless client.response.status == 303
        files = Dir[Rails.root.join("tmp/mail/*")]
        abort "README mail was not written" unless files.any?
        message = Mail.read(files.first)
        link = URI.parse(message.body.decoded[/http[^\\s]+/])
        abort "README fixed origin lost" unless link.host == "localhost" && link.port == 3000
        client.get link.request_uri
        abort "README confirmation failed" unless client.response.status == 200 && client.response.body.include?("Confirm your sign-in")
        puts "README trial verified"
      RUBY
      expect(result).to include("README trial verified")
    end
  end
end
