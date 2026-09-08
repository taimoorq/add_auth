# frozen_string_literal: true

require "socket"

# Loopback-only SMTP sink; the caller owns teardown and can reject one DATA.
class LocalSMTP
  attr_reader :messages, :attempts
  attr_accessor :reject_next

  def initialize
    @server = TCPServer.new("127.0.0.1", 0)
    @messages, @attempts = Queue.new, Queue.new
    @thread = Thread.new do
      loop do
        client = @server.accept
        client.write("220 localhost ESMTP\r\n")
        while (line = client.gets)
          case line
          when /\AEHLO/, /\AHELO/ then client.write("250 localhost\r\n")
          when /\AMAIL/, /\ARCPT/, /\ARSET/ then client.write("250 OK\r\n")
          when /\ADATA/
            client.write("354 Send message\r\n")
            body = +""
            while (part = client.gets) && part != ".\r\n"
              body << part
            end
            @attempts << true
            if reject_next
              self.reject_next = false
              client.write("450 Temporary local test failure\r\n")
            else
              @messages << body
              client.write("250 Accepted locally\r\n")
            end
          when /\AQUIT/
            client.write("221 Goodbye\r\n")
            break
          else client.write("250 OK\r\n")
          end
        end
        client.close
      end
    rescue IOError, Errno::EBADF
      nil
    end
  end

  def port = @server.addr[1]

  def close
    @server.close
    @thread.kill
    @thread.join
  end
end
