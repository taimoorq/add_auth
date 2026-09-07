# frozen_string_literal: true

require "open3"
require "rbconfig"

RSpec.describe "Core load boundary" do
  it "loads and hashes with explicit key material without loading Rails or Active Support" do
    code = <<~RUBY
      require "latchkey"
      abort "framework dependency leaked into Core" if defined?(Rails) || defined?(ActiveSupport)
      digest = Latchkey::Core::Digest::Hmac.new(salt: "test", secret: "s" * 32)
      abort "digest mismatch" unless digest.matches?(digest.digest("token"), "token")
    RUBY
    output, errors, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", code)
    expect(status.success?).to be(true), output + errors
  end
end
