# frozen_string_literal: true

RSpec.describe AddAuth::Result do
  describe ".success" do
    it "is a success with the given user and strategy" do
      user = Object.new
      result = described_class.success(user:, strategy: :email_link)

      expect(result).to be_success
      expect(result.user).to eq(user)
      expect(result.strategy).to eq(:email_link)
    end
  end

  describe ".failure" do
    it "is a failure with the given reason" do
      result = described_class.failure(reason: :invalid_credentials)

      expect(result).to be_failure
      expect(result.reason).to eq(:invalid_credentials)
    end

    it "rejects reasons outside the closed set" do
      expect {
        described_class.failure(reason: :made_up_reason)
      }.to raise_error(ArgumentError, /unknown Result reason/)
    end
  end
end
