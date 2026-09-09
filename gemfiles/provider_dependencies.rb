# frozen_string_literal: true

# Host-selected provider libraries, used only by the optional acceptance suite.
gem "puma"
gem "omniauth", "~> 2.1"
gem "omniauth-rails_csrf_protection", "~> 2.0", require: false
gem "omniauth-google-oauth2", "~> 1.2"
gem "omniauth_openid_connect", "~> 0.8"
gem "omniauth-apple", "~> 1.4"
gem "openid_connect", "~> 2.5"
gem "jwt", "~> 3.2"
gem "webrick", "~> 1.9"
