# frozen_string_literal: true

require_relative "mobile_callback_server"
require "base64"
require "digest"

module MobileProviderFixture
  def mobile_callback_url = "https://localhost:#{host.environment.fetch("MOBILE_CALLBACK_PORT")}/callback"

  def mobile_parameters
    {client_id: "android", callback: mobile_callback_url, state: @mobile_state,
     code_challenge: Base64.urlsafe_encode64(Digest::SHA256.digest(@mobile_verifier), padding: false), code_challenge_method: "S256"}
  end

  def mobile_fields
    uri = URI(browser.current_url)
    raise "wrong app callback" unless uri.to_s.split("?").first == mobile_callback_url
    fields = URI.decode_www_form(uri.query)
    raise "ambiguous app callback" unless fields.map(&:first).sort == %w[code state] && fields.to_h.fetch("state") == @mobile_state
    fields.to_h
  end

  def exchange_mobile(verifier: @mobile_verifier)
    mobile_request("POST", "/mobile/handoff", params: mobile_fields.merge(client_id: "android", code_verifier: verifier))
  end

  def mobile_request(method, path, params: nil, bearer: nil)
    uri = URI("#{origin}#{path}")
    connection = Net::HTTP.new(uri.host, uri.port)
    connection.open_timeout = connection.read_timeout = 5
    if uri.scheme == "https"
      connection.use_ssl = true
      # Trust only this fixture's generated localhost certificate. Normal TLS
      # chain and hostname checks remain active on the API exchange.
      connection.cert_store = OpenSSL::X509::Store.new.tap { |store| store.add_file(File.join(directory, "cert.pem")) }
    end
    request = Net::HTTP.const_get(method.capitalize).new(uri.request_uri)
    request["Content-Type"] = "application/json"
    request["Authorization"] = "Bearer #{bearer}" if bearer
    request.body = JSON.generate(params) if params
    connection.request(request)
  end

  private

  def prepare_mobile(mobile)
    @mobile = mobile
    @mobile_callback&.stop
    @mobile_callback = nil
    return unless mobile
    @mobile_state = SecureRandom.urlsafe_base64(32)
    @mobile_verifier = SecureRandom.urlsafe_base64(48)
    @mobile_callback = MobileCallbackServer.new(port: host.environment.fetch("MOBILE_CALLBACK_PORT").to_i)
  end
end
