# frozen_string_literal: true

module AddAuth
  module Rails
    module ProviderLibraries
      # Routing selects only host-registered AddAuth providers. Authentication
      # and transaction ownership are checked later by the library and Core.
      class CallbackRoute
        def self.matches?(request)
          options = AddAuth.configuration.external_identities
          options.enabled && options.providers.any? { |provider| provider.middleware_name == request.path_parameters[:provider] }
        end
      end
    end
  end
end
