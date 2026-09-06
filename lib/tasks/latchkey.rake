# frozen_string_literal: true

namespace :latchkey do
  desc "Audit Latchkey configuration for common misconfigurations (see docs/authentication-gem-plan.md section 11)"
  task doctor: :environment do
    # TODO(v1): implement the checks from section 11:
    #   - rp_id vs. the app's configured host (an rp_id mismatch permanently
    #     scopes existing passkeys -- this is the single highest-value check
    #     here, see section 6's "Hazard: RP ID")
    #   - cookie `secure` flag in production
    #   - challenge adapter configured wherever challenge_on names a form
    #   - mailer default_url_options present
    #   - session lifetime vs. idle timeout coherence
    #   - unique index on the configured identifier column
    #   - filter_parameters covering password/token/WebAuthn payloads
    #   - pending Latchkey migrations
    #   - ejected-file drift against the fingerprint each generated file carries
    warn "latchkey:doctor is not implemented yet -- see docs/authentication-gem-plan.md section 11"
  end
end
