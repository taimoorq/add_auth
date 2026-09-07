Rails.application.routes.draw do
  get "latchkey/application.js", to: "latchkey/assets#application"
  get "latchkey/codec.js", to: "latchkey/assets#codec"
  get "latchkey/passkey.js", to: "latchkey/assets#passkey"
  get "latchkey/stimulus.js", to: "latchkey/assets#stimulus"
  # Latchkey sign-in
  get "latchkey.css", to: "latchkey/assets#stylesheet"
  get "latchkey/turbo.js", to: "latchkey/assets#turbo"
  get "latchkey/boot.js", to: "latchkey/assets#boot"
  get "latchkey/challenge.js", to: "latchkey/assets#challenge"
  get "sign-in", to: "latchkey/sign_ins#new"
  post "sign-in/password", to: "latchkey/sign_ins#password"
  post "sign-in/email", to: "latchkey/sign_ins#request_link"
  get "sign-in/check-email", to: "latchkey/sign_ins#check_email"
  get "sign-in/link", to: "latchkey/sign_ins#link"
  post "sign-in/link", to: "latchkey/sign_ins#confirm"
  # Latchkey session management
  get "sessions/revoke-all", to: "latchkey/sessions#new_revoke_all"
  post "sessions/revoke-all", to: "latchkey/sessions#revoke_all"
  resources :security_sessions, path: "sessions", only: [:index, :destroy], controller: "latchkey/sessions"
  get "reauthenticate", to: "latchkey/reauthentications#new"
  post "reauthenticate/password", to: "latchkey/reauthentications#password"
  post "reauthenticate/email", to: "latchkey/reauthentications#request_link"
  get "reauthenticate/check-email", to: "latchkey/reauthentications#check_email"
  get "reauthenticate/link", to: "latchkey/reauthentications#link"
  post "reauthenticate/link", to: "latchkey/reauthentications#confirm"
  get "sensitive", to: "sensitive#show"
  patch "sensitive", to: "sensitive#update"
  get "sensitive/done", to: "sensitive#done"
  # Latchkey passkeys
  get "latchkey/passkey.js", to: "latchkey/assets#passkey"
  get "latchkey/codec.js", to: "latchkey/assets#codec"
  get "passkeys", to: "latchkey/passkeys#index"
  post "passkeys/options", to: "latchkey/passkeys#registration_options"
  post "passkeys", to: "latchkey/passkeys#register"
  post "passkeys/sign-in/options", to: "latchkey/passkeys#authentication_options"
  post "passkeys/sign-in", to: "latchkey/passkeys#authenticate"
  post "passkeys/cancel", to: "latchkey/passkeys#cancel"
  post "passkeys/policy", to: "latchkey/passkeys#change_policy"
  patch "passkeys/:id", to: "latchkey/passkeys#rename"
  delete "passkeys/:id", to: "latchkey/passkeys#remove"
  post "reauthenticate/passkey/options", to: "latchkey/passkeys#reauthentication_options"
  post "reauthenticate/passkey", to: "latchkey/passkeys#reauthenticate"
  get "recover", to: "latchkey/recoveries#new"
  post "recover/email", to: "latchkey/recoveries#request_link"
  get "recover/check-email", to: "latchkey/recoveries#check_email"
  get "recover/link", to: "latchkey/recoveries#link"
  post "recover/link", to: "latchkey/recoveries#confirm"
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
