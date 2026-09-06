# frozen_string_literal: true

RSpec.describe Latchkey::Core::Challenge do
  describe Latchkey::Core::Challenge::Null do
    it "always succeeds and exposes no site key" do
      verification = subject.verify(token: nil, remote_ip: nil, action: :sign_in)

      expect(verification).to be_success
      expect(subject.site_key).to be_nil
    end
  end

  describe Latchkey::Core::Challenge::Test do
    it "succeeds, rejects, or reports unavailable per its configured mode" do
      expect(described_class.new(mode: :success).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)).to be_success
      expect(described_class.new(mode: :rejected).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)).to be_rejected
      expect(described_class.new(mode: :unavailable).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)).to be_unavailable
    end

    it "rejects an unknown mode rather than silently succeeding" do
      expect {
        described_class.new(mode: :bogus).verify(token: "t", remote_ip: "1.2.3.4", action: :sign_in)
      }.to raise_error(ArgumentError, /unknown Test challenge mode/)
    end
  end
end
