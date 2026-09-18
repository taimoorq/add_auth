# frozen_string_literal: true

require "spec_helper"
require "rails"
require "rails/generators"
require "generators/add_auth/primary_key"

RSpec.describe AddAuth::Generators::PrimaryKey do
  it "rejects unsupported Rails generator types before interpolating migration source" do
    generator = Class.new { include AddAuth::Generators::PrimaryKey }.new
    configuration = double(generators: double(options: {active_record: {primary_key_type: :string}}))
    allow(Rails).to receive(:application).and_return(double(config: configuration))
    expect { generator.send(:authentication_primary_key_type) }.to raise_error(Thor::Error, /primary_key_type/)
  end
end
