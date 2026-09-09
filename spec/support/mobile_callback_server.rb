# frozen_string_literal: true

require "webrick"
require "webrick/https"

# A synthetic claimed HTTPS app link endpoint. The real browser follows the
# generated 303 to this TLS server; no middleware rewrites the callback.
class MobileCallbackServer
  def initialize(port:)
    started = Queue.new
    @server = WEBrick::HTTPServer.new(Port: port, BindAddress: "127.0.0.1", SSLEnable: true,
      SSLCertName: [["CN", "localhost"]], StartCallback: -> { started << true },
      Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
    @server.mount_proc("/callback") do |_request, response|
      response["Content-Type"] = "text/html"
      response["Cache-Control"] = "no-store"
      response["Referrer-Policy"] = "no-referrer"
      response.body = "<!doctype html><title>Mobile callback</title><h1>Return to the app</h1>"
    end
    @thread = Thread.new { @server.start }
    started.pop
  end

  def stop
    @server.shutdown
    @thread.join
  end
end
