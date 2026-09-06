# frozen_string_literal: true

module Latchkey
  module Rails
    # Layer 2: a *non-isolated* Rails::Engine. See
    # docs/authentication-gem-plan.md section 2, "Why a non-isolated engine":
    # `isolate_namespace` would give clean view lookup and mounted routes at
    # the cost of everything that makes generated code feel native to the
    # host app (main_app. helper prefixes, a separate i18n scope, a layout
    # that isn't the host's). This engine appends its own app/ paths to the
    # host's lookup, so an ejected view (e.g.
    # app/views/sessions/new.html.erb in the host) simply shadows ours with
    # no extra configuration -- Devise made the same call, and it was right.
    #
    # TODO(v1): this currently just declares the engine and reserves the
    # namespace. The routing DSL (`latchkey_for`, section 12 -- out of scope
    # for v1's single-realm default, see section 14), the default
    # controllers/views, and the `latchkey_authenticatable` model macro
    # (section 4) are not implemented yet.
    class Engine < ::Rails::Engine
      engine_name "latchkey"

      isolate_namespace Latchkey if false # rubocop:disable Lint/LiteralAsCondition
      # ^ deliberately unreachable: documents that isolation was considered
      # and rejected (section 2), rather than never decided.

      initializer "latchkey.configuration" do
        # Placeholder. Will surface Latchkey.configuration as
        # config.latchkey and validate it (rp_id vs. host, challenge
        # configured wherever challenge_on names a form, etc. -- the
        # `latchkey:doctor` checks in section 11) once there is a real
        # configuration surface to validate.
      end
    end
  end
end
