import { Controller } from "/latchkey/stimulus.js"
import { application } from "/latchkey/application.js"
import { options, credential } from "/latchkey/codec.js"

export class PasskeyController extends Controller {
  static targets = ["form", "controls", "unavailable", "status", "button"]
  static values = { optionsUrl: String, finishUrl: String, mode: String, purpose: String, csrf: String, conditional: Boolean }
  connect() {
    this.generation = 0
    this.active = true
    if (!window.PublicKeyCredential || !navigator.credentials || !window.isSecureContext) return
    this.controlsTarget.hidden = false
    this.unavailableTarget.hidden = true
    if (this.conditionalValue && PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then(available => {
        if (available && this.active && !this.abort) this.run(true)
      }).catch(() => {})
    }
  }
  submit(event) {
    if (event.defaultPrevented) return
    event.preventDefault()
    this.run(false)
  }
  otherSubmission(event) { if (event.target !== this.formTarget) this.stop() }
  disconnect() { this.active = false; this.stop() }
  beforeCache() { this.active = false; this.stop(); this.controlsTarget.hidden = true; this.unavailableTarget.hidden = false; this.message("") }
  async run(conditional) {
    this.stop()
    const generation = this.generation
    this.abort = new AbortController()
    if (!conditional) { this.buttonTarget.disabled = true; this.message("Follow your browser’s passkey prompt.") }
    try {
      const challenge = new FormData(this.formTarget).get("challenge_token")
      const start = await this.post(this.optionsUrlValue, { purpose: this.purposeValue || null, challenge_token: challenge }, this.abort.signal)
      this.formTarget.dispatchEvent(new CustomEvent("latchkey:proof-used"))
      if (!this.current(generation)) return
      if (start.redirect) { this.navigate(start.redirect); return }
      this.transaction = start.transaction
      const create = this.modeValue === "create"
      const request = { publicKey: options(start.publicKey, create), signal: this.abort.signal }
      if (conditional) request.mediation = "conditional"
      const proof = await navigator.credentials[create ? "create" : "get"](request)
      if (!this.current(generation)) return
      const result = await this.post(this.finishUrlValue, { transaction: this.transaction, credential: credential(proof) }, this.abort.signal)
      if (!this.current(generation)) return
      this.transaction = null
      this.navigate(result.redirect)
    } catch (error) {
      if (this.current(generation) && error.name !== "AbortError") {
        this.message(error.name === "NotAllowedError" ? "No change was made. Try again, use another passkey, or choose an allowed recovery method." : error.message)
        if (!conditional) this.statusTarget.focus()
      }
    } finally {
      if (this.current(generation)) { this.buttonTarget.disabled = false; this.stop() }
    }
  }
  async post(path, body, signal) {
    const response = await fetch(path, { method: "POST", credentials: "same-origin", signal,
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": this.csrfValue }, body: JSON.stringify(body) })
    const value = await response.json()
    if (!response.ok && !value.redirect) throw new Error(value.error || "Verification is unavailable. Try again shortly.")
    return value
  }
  stop() {
    this.generation += 1
    this.abort?.abort()
    this.abort = null
    if (this.transaction) {
      fetch("/passkeys/cancel", { method: "POST", credentials: "same-origin", keepalive: true,
        headers: { "Content-Type": "application/json", "X-CSRF-Token": this.csrfValue },
        body: JSON.stringify({ transaction: this.transaction }) }).catch(() => {})
      this.transaction = null
    }
    if (this.hasButtonTarget) this.buttonTarget.disabled = false
  }
  current(generation) { return this.active && this.element.isConnected && this.generation === generation }
  message(text) { this.statusTarget.textContent = text; this.statusTarget.hidden = !text }
  navigate(path) { if (path) window.Turbo ? window.Turbo.visit(path) : window.location.assign(path) }
}
application.register("latchkey-passkey", PasskeyController)
