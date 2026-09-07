# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Default authentication colors" do
  it "maintains AA text and visible control/focus contrast" do
    css = File.read(File.expand_path("../../..", __dir__) + "/lib/generators/latchkey/email_link/templates/latchkey.css")
    colors = css.scan(/--latchkey-([a-z]+): (#[0-9a-f]{6})/).to_h
    luminance = ->(hex) do
      channels = hex.delete_prefix("#").scan(/../).map do |pair|
        value = pair.to_i(16) / 255.0
        (value <= 0.04045) ? value / 12.92 : ((value + 0.055) / 1.055)**2.4
      end
      channels.zip([0.2126, 0.7152, 0.0722]).sum { |channel, weight| channel * weight }
    end
    [%w[text surface], %w[text canvas], %w[muted surface], %w[accent surface]].each do |foreground, background|
      values = [luminance.call(colors.fetch(foreground)), luminance.call(colors.fetch(background))].sort
      expect((values.last + 0.05) / (values.first + 0.05)).to be >= 4.5
    end
    %w[border focus].each do |role|
      values = [luminance.call(colors.fetch(role)), luminance.call(colors.fetch("surface"))].sort
      expect((values.last + 0.05) / (values.first + 0.05)).to be >= 3
    end
  end
end
