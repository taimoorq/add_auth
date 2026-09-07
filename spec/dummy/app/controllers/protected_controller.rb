class ProtectedController < ApplicationController
  def index
    render html: "Signed in"
  end
end
