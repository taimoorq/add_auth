Rails.application.routes.draw do
  get "mobile/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "mobile"}
  post "mobile/handoff", to: "add_auth/mobile_sessions#exchange"
  post "mobile/apple/challenge", to: "add_auth/mobile_sessions#apple_challenge"
  post "mobile/apple/session", to: "add_auth/mobile_sessions#apple"
  post "mobile/apple/enrollment", to: "add_auth/mobile_sessions#apple_enroll"
  post "mobile/session", to: "add_auth/mobile_sessions#create"
  get "mobile/session", to: "add_auth/mobile_sessions#show"
  delete "mobile/session", to: "add_auth/mobile_sessions#destroy"
  get "mobile/sessions", to: "add_auth/mobile_sessions#index"
  delete "mobile/sessions/:id", to: "add_auth/mobile_sessions#revoke"
  post "mobile/sessions/revoke-all", to: "add_auth/mobile_sessions#revoke_all"
  # AddAuth external provider callbacks
  get "account/sign-up/providers/:provider", to: "add_auth/provider_sign_ins#enrollment", defaults: {flow: "enroll"}
  post "account/sign-up/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "enroll"}
  post "sign-in/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "sign_in"}
  post "account/external-identities/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "link"}
  get "account/external-identities", to: "add_auth/external_identities#index"
  delete "account/external-identities/:id", to: "add_auth/external_identities#destroy"
  post "reauthenticate/providers/:provider", to: "add_auth/provider_sign_ins#prepare", defaults: {flow: "reauthenticate"}
  match "auth/:provider/callback", to: "add_auth/provider_sign_ins#callback", via: [:get, :post], constraints: AddAuth::Rails::ProviderLibraries::CallbackRoute
  get "add_auth/application.js", to: "add_auth/assets#application"
  get "add_auth/codec.js", to: "add_auth/assets#codec"
  get "add_auth/passkey.js", to: "add_auth/assets#passkey"
  get "add_auth/stimulus.js", to: "add_auth/assets#stimulus"
  # AddAuth sign-in
  get "add_auth.css", to: "add_auth/assets#stylesheet"
  get "add_auth/turbo.js", to: "add_auth/assets#turbo"
  get "add_auth/boot.js", to: "add_auth/assets#boot"
  get "add_auth/challenge.js", to: "add_auth/assets#challenge"
  get "sign-in", to: "add_auth/sign_ins#new"
  post "sign-in/password", to: "add_auth/sign_ins#password"
  post "sign-in/email", to: "add_auth/sign_ins#request_link"
  get "sign-in/check-email", to: "add_auth/sign_ins#check_email"
  get "sign-in/link", to: "add_auth/sign_ins#link"
  post "sign-in/link", to: "add_auth/sign_ins#confirm"
  # AddAuth session management
  get "sessions/revoke-all", to: "add_auth/sessions#new_revoke_all"
  post "sessions/revoke-all", to: "add_auth/sessions#revoke_all"
  resources :security_sessions, path: "sessions", only: [:index, :destroy], controller: "add_auth/sessions"
  get "reauthenticate", to: "add_auth/reauthentications#new"
  post "reauthenticate/password", to: "add_auth/reauthentications#password"
  post "reauthenticate/email", to: "add_auth/reauthentications#request_link"
  get "reauthenticate/check-email", to: "add_auth/reauthentications#check_email"
  get "reauthenticate/link", to: "add_auth/reauthentications#link"
  post "reauthenticate/link", to: "add_auth/reauthentications#confirm"
  get "sensitive", to: "sensitive#show"
  patch "sensitive", to: "sensitive#update"
  get "sensitive/done", to: "sensitive#done"
  # AddAuth passkeys
  get "add_auth/passkey.js", to: "add_auth/assets#passkey"
  get "add_auth/codec.js", to: "add_auth/assets#codec"
  get "passkeys", to: "add_auth/passkeys#index"
  post "passkeys/options", to: "add_auth/passkeys#registration_options"
  post "passkeys", to: "add_auth/passkeys#register"
  post "passkeys/sign-in/options", to: "add_auth/passkeys#authentication_options"
  post "passkeys/sign-in", to: "add_auth/passkeys#authenticate"
  post "passkeys/cancel", to: "add_auth/passkeys#cancel"
  post "passkeys/policy", to: "add_auth/passkeys#change_policy"
  patch "passkeys/:id", to: "add_auth/passkeys#rename"
  delete "passkeys/:id", to: "add_auth/passkeys#remove"
  post "reauthenticate/passkey/options", to: "add_auth/passkeys#reauthentication_options"
  post "reauthenticate/passkey", to: "add_auth/passkeys#reauthenticate"
  get "recover", to: "add_auth/recoveries#new"
  post "recover/email", to: "add_auth/recoveries#request_link"
  get "recover/check-email", to: "add_auth/recoveries#check_email"
  get "recover/link", to: "add_auth/recoveries#link"
  post "recover/link", to: "add_auth/recoveries#confirm"
  resource :session
  resources :passwords, param: :token
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", :as => :rails_health_check

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/")
  root "protected#index"
end
