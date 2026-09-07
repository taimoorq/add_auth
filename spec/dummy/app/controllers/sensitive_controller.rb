class SensitiveController < ApplicationController
  require_elevated_session purpose: :manage_profile, only: :update

  def show
    render inline: '<h1>Review profile change</h1><%= form_with url: "/sensitive", method: :patch do |form| %><%= form.submit "Confirm profile change" %><% end %>'
  end

  def update
    result = with_elevated_session(purpose: :manage_profile) do |account|
      # This harmless fixture write models a host-authorized database mutation.
      account.update!(updated_at: Time.current)
    end
    return head :forbidden unless result.success?
    redirect_to "/sensitive/done", status: :see_other
  end

  def done
    render html: "Profile change completed"
  end
end
