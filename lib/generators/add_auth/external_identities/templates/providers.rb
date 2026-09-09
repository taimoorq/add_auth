# frozen_string_literal: true

# External provider support is opt-in. Add only the provider gems you use to
# the host application's Gemfile, then configure their OmniAuth middleware
# using their normal configuration. Reuse existing registrations rather than
# adding a second OmniAuth::Builder for the same provider. Keep the host's CSRF
# validator, scopes, request methods and failure handler. AddAuth changes none
# of them. Keep issuer/audience fixed; never derive them from a request, Host
# header, profile attribute, or callback parameter.
#
# AddAuth's correlation middleware goes before OmniAuth::Builder. It retains
# opaque Core transaction data only. OmniAuth (or the selected OIDC library)
# owns code exchange, state, nonce, JWKS/signature, issuer, audience and expiry.
# Requests without an AddAuth transaction continue through the existing stack.
# Generated callback routes select only enabled, explicitly registered providers.
# Review routing precedence before adopting a provider with an existing callback.
# Custom provider paths/callbacks require an explicit host integration; do not
# rewrite an existing library configuration to fit this conventional-path example.
#
# require "omniauth"
# require "omniauth-google-oauth2"
# require "add_auth/rails/provider_libraries/omniauth"
# require "add_auth/rails/provider_libraries/omniauth_correlation"
# Rails.application.config.middleware.use AddAuth::Rails::ProviderLibraries::OmniAuthCorrelation,
#   providers: ["google_oauth2"]
# Rails.application.config.middleware.use OmniAuth::Builder do
#   provider :google_oauth2, ENV.fetch("GOOGLE_CLIENT_ID"), ENV.fetch("GOOGLE_CLIENT_SECRET")
# end
#
# verifier = AddAuth::Rails::ProviderLibraries::OmniAuth::Verifier.new(
#   provider: "google_oauth2", provenance: "omniauth-google-oauth2",
#   mapping: {issuer: %i[extra id_info iss], audience: %i[extra id_info aud], subject: %i[extra id_info sub],
#             authenticated_at: %i[extra id_info auth_time]}
# )
# AddAuth.configure do |config|
#   config.external_identities.register(
#     id: "google", label: "Google", middleware_name: "google_oauth2",
#     configuration: AddAuth::Core::ExternalIdentities::Configuration.new(
#       id: "google", issuer: "https://accounts.google.com", audience: ENV.fetch("GOOGLE_CLIENT_ID"), verifier: verifier
#     )
#   )
#   config.external_identities.enabled = true
# end
#
# Apple form_post needs its own callback-only cookie wrapper before
# OmniAuth::Builder. Do not weaken your normal Rails session cookie:
#
# require "omniauth-apple"
# require "add_auth/rails/provider_libraries/apple_form_post_correlation"
# Rails.application.config.middleware.use AddAuth::Rails::ProviderLibraries::AppleFormPostCorrelation,
#   key: Rails.application.key_generator.generate_key("add_auth.apple-form-post.v1", 32)
