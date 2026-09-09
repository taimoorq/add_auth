# frozen_string_literal: true

require_relative "isolated_host"
require_relative "mobile_provider_fixture"
require "net/http"
require "socket"
require "pg"
require "selenium-webdriver"

class MicrosoftOidcHost
  include MobileProviderFixture

  attr_reader :directory, :host, :browser

  def initialize(directory)
    @directory = directory
    database = ENV.fetch("ADD_AUTH_MICROSOFT_DATABASE_URL")
    uri = URI(database)
    unless %w[postgres postgresql].include?(uri.scheme) && uri.path == "/add_auth_external_test" && uri.query.nil?
      raise "Use the dedicated disposable PostgreSQL add_auth_external_test database"
    end
    @connection = PG.connect(database)
    @schema = "microsoft_browser_#{SecureRandom.hex(8)}"
    @connection.exec("CREATE SCHEMA #{@schema}")
    @app_port, @idp_port = unused_port, unused_port
    @host = IsolatedHost.new(directory)
    host.environment.merge!("RACK_ENV" => "test", "DATABASE_URL" => "#{database}?schema_search_path=#{@schema}",
      "MICROSOFT_APP_PORT" => @app_port.to_s, "MICROSOFT_IDP_PORT" => @idp_port.to_s, "MOBILE_CALLBACK_PORT" => unused_port.to_s)
    host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: %w[omniauth_openid_connect pg])
    host.run("generate", "authentication")
    users = Dir[File.join(host.root, "db/migrate/*_create_users.rb")].fetch(0)
    sessions = Dir[File.join(host.root, "db/migrate/*_create_sessions.rb")].fetch(0)
    File.write(users, File.read(users).sub("create_table :users do", "create_table :users, id: :uuid do"))
    File.write(sessions, File.read(sessions).sub("t.references :user,", "t.references :user, type: :uuid,"))
    host.run("generate", "add_auth:session_upgrade")
    host.run("generate", "add_auth:external_identities")
    host.run("generate", "add_auth:mobile_sessions")
    host.configure
    host.run("db:migrate")
    if ENV["ADD_AUTH_EJECT_UI"] == "1"
      host.runner(<<~RUBY)
        require "add_auth/rails/ejection"
        ejection = AddAuth::Rails::Ejection.new(host_root: Rails.root)
        %i[views controllers javascript].each { |kind| ejection.install(kind: kind) }
        abort "Microsoft provider view was not ejected" unless File.file?(Rails.root.join("app/views/add_auth/provider_sign_ins/_prepare.html.erb"))
      RUBY
    end
    File.write(File.join(host.root, "config/initializers/zz_microsoft_browser.rb"), <<~RUBY)
      require #{File.expand_path("microsoft_oidc_server", __dir__).inspect}
      MicrosoftOidcServer.configure(Rails.application)
    RUBY
    File.write(File.join(host.root, "app/controllers/fixture_home_controller.rb"), <<~RUBY)
      class FixtureHomeController < ApplicationController
        def index
          render plain: "Signed in UUID \#{Current.user.id} through \#{Current.session.authenticated_with}"
        end
      end
    RUBY
    routes = File.join(host.root, "config/routes.rb")
    File.write(routes, File.read(routes).sub("Rails.application.routes.draw do", <<~RUBY.chomp))
      Rails.application.routes.draw do
        root to: "fixture_home#index"
        # The host owns its failure landing and unrelated callback. AddAuth must
        # not install or replace OmniAuth's global failure handler to reach it.
        get "/auth/failure", to: ->(_env) { [422, {"content-type" => "text/plain"}, ["Host OAuth failure landing"]] }
        get "/auth/host_owned/callback", to: ->(_env) { [200, {"content-type" => "text/plain"}, ["Unrelated host callback retained"]] }
    RUBY
    server_file = File.join(directory, "server.rb")
    File.write(server_file, <<~RUBY)
      require_relative "host/config/environment"
      require "puma"
      MicrosoftOidcServer.seed!
      app = Puma::Server.new(Rails.application, Puma::Events.new)
      app.add_tcp_listener("127.0.0.1", #{@app_port})
      idp = Puma::Server.new(MicrosoftOidcServer.method(:idp), Puma::Events.new)
      idp.add_tcp_listener("127.0.0.1", #{@idp_port})
      trap("TERM") { app.stop; idp.stop }
      app.run
      idp.run.join
    RUBY
    @pid = host.spawn(server_file, log: "microsoft-server.log")
    wait_until { control("status") }
  rescue
    close
    raise
  end

  def start(mode: "valid", javascript: true, turbo: false, mobile: false)
    browser&.quit
    prepare_mobile(mobile)
    control("reset?mode=#{mode}&turbo=#{turbo}")
    options = Selenium::WebDriver::Chrome::Options.new
    options.add_argument("--headless=new")
    options.add_argument("--window-size=1280,900")
    options.accept_insecure_certs = true if mobile
    options.add_preference("profile.managed_default_content_settings.javascript", 2) unless javascript
    @browser = Selenium::WebDriver.for(:chrome, options: options)
    browser.navigate.to("#{origin}/auth/host_owned/callback")
    raise "Host callback was intercepted" unless browser.find_element(tag_name: "body").text == "Unrelated host callback retained"
    browser.navigate.to("#{origin}/sign-in")
    raise "Turbo unexpectedly loaded" if javascript && !turbo && browser.execute_script("return typeof window.Turbo") != "undefined"
    if mobile
      browser.navigate.to("#{origin}/mobile/providers/microsoft?#{URI.encode_www_form(mobile_parameters)}")
    else
      click("Continue with Microsoft")
    end
    wait_until { browser.find_element(tag_name: "h1").text == "Continue to Microsoft" }
    click("Continue with Microsoft")
    wait_until { browser.current_url.start_with?(idp_origin) && browser.find_element(tag_name: "h1").text == "Local Microsoft identity provider" }
    @callback = browser.find_element(id: "microsoft-return").attribute("href")
    @session_cookie = browser.execute_cdp("Network.getAllCookies").fetch("cookies").find { |cookie| cookie["name"] == "_microsoft_browser_fixture" }
    self
  end

  def submit
    browser.find_element(id: "microsoft-return").click
    wait_until { browser.current_url.start_with?(@mobile ? mobile_callback_url : origin) && !status.fetch("callbacks").empty? }
    status
  end

  def replay
    # Restore the browser's own pre-callback cookie to reach the provider's
    # real single-use code exchange. No strategy/auth hash is manufactured.
    browser.execute_cdp("Network.setCookie", **@session_cookie.slice("name", "value", "domain", "path", "secure", "httpOnly", "sameSite"))
    browser.navigate.to(@callback)
    wait_until { status.fetch("callbacks").size == 2 }
    status
  end

  def status = JSON.parse(control("status"))
  def origin = "http://localhost:#{@app_port}"
  def idp_origin = "http://127.0.0.1:#{@idp_port}"

  def close
    browser&.quit
    @mobile_callback&.stop
  ensure
    if @pid
      begin
        Process.kill("TERM", @pid)
        Process.wait(@pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
      @pid = nil
    end
    if @connection
      @connection.exec("DROP SCHEMA IF EXISTS #{@schema} CASCADE") if @schema
      @connection.close
      @connection = nil
    end
  end

  private

  def control(path) = Net::HTTP.get(URI("#{idp_origin}/#{path}"))

  def click(text)
    button = wait_until do
      browser.find_elements(css: "button,input[type=submit]").find { |item| item.text == text || item.attribute("value") == text }
    end
    button.click
  end

  def wait_until
    Selenium::WebDriver::Wait.new(timeout: 20, interval: 0.1,
      ignore: [Errno::ECONNREFUSED, EOFError, Selenium::WebDriver::Error::NoSuchElementError, Selenium::WebDriver::Error::StaleElementReferenceError]).until do
      yield
    rescue Selenium::WebDriver::Error::UnknownError => error
      # Chrome 152 classifies this detached-node read as UnknownError. Retry
      # only that read within the existing timeout; clicks remain outside.
      raise unless error.message.include?("Node with given id does not belong to the document")
      false
    end
  rescue Selenium::WebDriver::Error::TimeoutError
    raise "Microsoft browser fixture timeout; server output:\n#{File.read(File.join(directory, "microsoft-server.log"))}"
  end

  def unused_port = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }
end
