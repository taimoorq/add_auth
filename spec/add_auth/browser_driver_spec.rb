# frozen_string_literal: true

require "spec_helper"
require_relative "../support/browser"

RSpec.describe AddAuthDetachedDocumentRead do
  %i[visible_text visible?].each do |read|
    it "reclassifies only detached-document #{read}, preserving other driver failures and actions" do
      node = Class.new do
        attr_accessor :error
        def visible_text = raise(error)
        def visible? = raise(error)
        def click = raise(error)
        prepend AddAuthDetachedDocumentRead
      end.new
      node.error = Selenium::WebDriver::Error::UnknownError.new("Node with given id does not belong to the document")
      expect { node.public_send(read) }.to raise_error(Selenium::WebDriver::Error::StaleElementReferenceError)
      expect { node.click }.to raise_error(Selenium::WebDriver::Error::UnknownError)
      node.error = Selenium::WebDriver::Error::UnknownError.new("browser crashed")
      expect { node.public_send(read) }.to raise_error(Selenium::WebDriver::Error::UnknownError, /browser crashed/)
    end
  end
end
