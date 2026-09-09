# frozen_string_literal: true

require_relative "isolated_host"
require_relative "mobile_provider_fixture"
require "net/http"
require "socket"
require "openssl"
require "selenium-webdriver"

class AppleFormPostHost
  include MobileProviderFixture

  attr_reader :directory, :host, :browser, :start_cookies

  def initialize(directory)
    @directory = directory
    @app_port, @idp_port = unused_port, unused_port
    @host = IsolatedHost.new(directory)
    host.environment.merge!("APPLE_HTTPS_PORT" => @app_port.to_s, "APPLE_IDP_PORT" => @idp_port.to_s, "MOBILE_CALLBACK_PORT" => unused_port.to_s)
    host.install(IsolatedHost.candidate(directory), label: "candidate", extra_gems: %w[omniauth-apple webmock])
    host.run("generate", "authentication")
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
        abort "Apple provider view was not ejected" unless File.file?(Rails.root.join("app/views/add_auth/provider_sign_ins/_prepare.html.erb"))
      RUBY
    end
    File.write(File.join(host.root, "config/initializers/zz_apple_https.rb"), <<~RUBY)
      require #{File.expand_path("apple_form_post_server", __dir__).inspect}
      AppleFormPostServer.configure(Rails.application)
    RUBY
    File.write(File.join(host.root, "app/controllers/fixture_home_controller.rb"), <<~RUBY)
      class FixtureHomeController < ApplicationController
        def index
          render plain: "Signed in as \#{Current.user.email_address} through \#{Current.session.authenticated_with}"
        end
      end
    RUBY
    routes = File.join(host.root, "config/routes.rb")
    File.write(routes, File.read(routes).sub("Rails.application.routes.draw do", "Rails.application.routes.draw do\n  root to: 'fixture_home#index'"))
    certificate!
    server_file = File.join(directory, "server.rb")
    File.write(server_file, <<~RUBY)
      require_relative "host/config/environment"
      require "puma"
      AppleFormPostServer.seed!
      app = Puma::Server.new(Rails.application, Puma::Events.new)
      tls = Puma::MiniSSL::Context.new
      tls.key = #{File.join(directory, "key.pem").inspect}
      tls.cert = #{File.join(directory, "cert.pem").inspect}
      app.add_ssl_listener("127.0.0.1", #{@app_port}, tls)
      idp = Puma::Server.new(AppleFormPostServer.method(:idp), Puma::Events.new)
      idp.add_tcp_listener("127.0.0.1", #{@idp_port})
      trap("TERM") { app.stop; idp.stop }
      app.run
      idp.run.join
    RUBY
    @pid = host.spawn(server_file, log: "https-server.log")
    wait_until { control("status") }
  end

  def start(mode: "valid", browser_mode: "turbo", mobile: false)
    browser&.quit
    prepare_mobile(mobile)
    control("reset?mode=#{mode}&browser_mode=#{browser_mode}")
    options = Selenium::WebDriver::Chrome::Options.new
    options.add_argument("--headless=new")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--window-size=1280,900")
    options.add_preference("profile.managed_default_content_settings.javascript", 2) if browser_mode == "no_js"
    @browser = Selenium::WebDriver.for(:chrome, options: options)
    browser.navigate.to("#{origin}/sign-in")
    raise "Turbo loaded in the ordinary HTML host" if browser_mode == "html" && browser.execute_script("return typeof window.Turbo") != "undefined"
    if mobile
      browser.navigate.to("#{origin}/mobile/providers/apple?#{URI.encode_www_form(mobile_parameters)}")
    else
      click("Continue with Apple")
    end
    wait_until { browser.find_element(tag_name: "h1").text == "Continue to Apple" }
    click("Continue with Apple")
    wait_until { browser.current_url.start_with?(idp_origin) && browser.find_element(tag_name: "h1").text == "Local Apple identity provider" }
    @form = browser.find_elements(css: "input").to_h { |input| [input.attribute("name"), input.attribute("value")] }
    issued_cookies = cookies
    @start_cookies = issued_cookies.map { |cookie| cookie.except("value") }
    @capsule = issued_cookies.find { |cookie| cookie["name"] == "add_auth_apple_callback" }
    self
  end

  def submit
    click("Return from Apple")
    wait_until { browser.current_url.start_with?(@mobile ? mobile_callback_url : origin) }
    wait_until { !status.fetch("callbacks").empty? }
    status
  end

  def replay
    # Restore only the captured opaque capsule and repeat the same cross-site
    # browser POST. This proves Core replay rejection even if cookie deletion
    # is bypassed by a client replaying its own previously issued cookie.
    browser.execute_cdp("Network.setCookie", **@capsule.slice("name", "value", "domain", "path", "secure", "httpOnly", "sameSite"))
    browser.navigate.to("#{idp_origin}/missing")
    browser.execute_script(<<~JS, "#{origin}/auth/apple/callback", @form)
      document.body.textContent = '';
      const form = document.createElement('form'); form.method='post'; form.action=arguments[0];
      for (const [name,value] of Object.entries(arguments[1])) {const field=document.createElement('input');field.name=name;field.value=value;form.appendChild(field);}
      const button=document.createElement('button');button.textContent='Replay callback';form.appendChild(button);document.body.appendChild(form);
    JS
    click("Replay callback")
    wait_until { status.fetch("callbacks").length == 2 }
    status
  end

  def cookies = browser.execute_cdp("Network.getAllCookies").fetch("cookies")
  def status = JSON.parse(control("status"))
  def origin = "https://localhost:#{@app_port}"
  def idp_origin = "http://127.0.0.1:#{@idp_port}"

  def close
    browser&.quit
    @mobile_callback&.stop
    return unless @pid
    Process.kill("TERM", @pid)
    Process.wait(@pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  private

  def control(path)
    Net::HTTP.get(URI("#{idp_origin}/#{path}"))
  end

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
      # Chrome 152 reports this detached-node read as UnknownError rather than
      # StaleElementReferenceError. These waits only read; clicks stay outside.
      raise unless error.message.include?("Node with given id does not belong to the document")
      false
    end
  rescue Selenium::WebDriver::Error::TimeoutError
    raise "Apple HTTPS fixture timeout; server output:\n#{File.read(File.join(directory, "https-server.log"))}"
  end

  def unused_port
    TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }
  end

  def certificate!
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=localhost")
    cert.public_key = key.public_key
    cert.not_before, cert.not_after = Time.now - 60, Time.now + 3600
    extensions = OpenSSL::X509::ExtensionFactory.new
    extensions.subject_certificate = extensions.issuer_certificate = cert
    cert.add_extension(extensions.create_extension("subjectAltName", "DNS:localhost"))
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    File.write(File.join(directory, "key.pem"), key.to_pem, perm: 0o600)
    File.write(File.join(directory, "cert.pem"), cert.to_pem)
  end
end
