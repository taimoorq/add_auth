import { Controller } from "/add_auth/stimulus.js"
import { application } from "/add_auth/application.js"

const scripts = new Map()
function loadScript(url) {
  if (!url) return Promise.resolve()
  if (!scripts.has(url)) {
    scripts.set(url, new Promise((resolve, reject) => {
      const script = document.createElement("script")
      const timer = setTimeout(() => { script.remove(); reject(new Error("unavailable")) }, 15000)
      script.src = url
      script.async = true
      script.onload = () => { clearTimeout(timer); resolve() }
      script.onerror = () => { clearTimeout(timer); script.remove(); reject(new Error("unavailable")) }
      document.head.append(script)
    }).catch(error => { scripts.delete(url); throw error }))
  }
  return scripts.get(url)
}

class ChallengeController extends Controller {
  static targets = ["token", "widget", "status", "submit"]
  static values = { provider: String, siteKey: String, action: String, scriptUrl: String }

  connect() {
    this.generation = (this.generation || 0) + 1
    this.active = true
    this.pending = false
    this.allowSubmit = false
    this.tokenTarget.value = ""
    this.prepare()
  }

  async prepare() {
    const generation = this.generation
    this.setDisabled(true)
    this.message("Verification is loading.")
    try {
      await loadScript(this.scriptUrlValue)
      if (!this.current(generation)) return
      this.provider = this.providerValue === "turnstile" ? window.turnstile : window.grecaptcha
      if (!this.provider) throw new Error("unavailable")
      if (this.providerValue === "recaptcha-v3") {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("unavailable")), 15000)
          this.provider.ready(() => { clearTimeout(timer); resolve() })
        })
      } else {
        this.widgetTarget.hidden = false
        const options = {
          sitekey: this.siteKeyValue,
          callback: token => {
            if (this.current(generation)) { this.tokenTarget.value = token; this.setDisabled(false); this.message("") }
          },
          "expired-callback": () => { if (this.current(generation)) { this.tokenTarget.value = ""; this.setDisabled(true) } },
          "error-callback": () => { if (this.current(generation)) this.unavailable() }
        }
        if (this.providerValue === "turnstile") Object.assign(options, { action: this.actionValue, "response-field": false })
        this.widgetId = this.provider.render(this.widgetTarget, options)
      }
      if (this.current(generation)) {
        this.ready = true
        if (this.providerValue === "recaptcha-v3") { this.setDisabled(false); this.message("") }
      }
    } catch (_) { if (this.current(generation)) this.unavailable() }
  }

  async submit(event) {
    if (this.allowSubmit) { this.allowSubmit = false; return }
    if (this.pending) { event.preventDefault(); event.stopImmediatePropagation(); return }
    // Server-side verification remains authoritative when loading fails.
    if (!this.ready || this.providerValue !== "recaptcha-v3") return
    event.preventDefault()
    event.stopImmediatePropagation()
    const generation = this.generation
    const submitter = event.submitter
    this.pending = true
    this.setDisabled(true)
    try {
      const token = await Promise.race([
        this.provider.execute(this.siteKeyValue, { action: this.actionValue }),
        new Promise((_, reject) => { this.executionTimer = setTimeout(() => reject(new Error("unavailable")), 15000) })
      ])
      if (!this.current(generation)) return
      this.tokenTarget.value = typeof token === "string" ? token : ""
      // Even an already-resolved provider promise must leave the original
      // submit event before requestSubmit; browsers reject recursive submits.
      await new Promise(resolve => setTimeout(resolve, 0))
      if (!this.current(generation)) return
      this.allowSubmit = true
      this.setDisabled(false)
      this.element.requestSubmit(submitter)
    } catch (_) { if (this.current(generation)) this.unavailable() }
    finally { clearTimeout(this.executionTimer); if (this.current(generation)) this.pending = false }
  }

  reset() {
    this.tokenTarget.value = ""
    this.allowSubmit = false
    if (this.widgetId !== undefined && this.provider) {
      this.setDisabled(true)
      this.provider.reset(this.widgetId)
    }
  }

  beforeCache() { this.teardown() }
  disconnect() { this.teardown() }
  teardown() {
    this.active = false
    this.generation = (this.generation || 0) + 1
    clearTimeout(this.executionTimer)
    this.tokenTarget.value = ""
    this.setDisabled(false)
    if (this.widgetId !== undefined && this.provider) {
      if (this.providerValue === "turnstile") this.provider.remove(this.widgetId)
      else this.provider.reset(this.widgetId)
      this.widgetId = undefined
      this.widgetTarget.replaceChildren()
    }
    this.ready = false
  }

  current(generation) { return this.active && this.element.isConnected && this.generation === generation }
  setDisabled(value) { this.submitTargets.forEach(button => { button.disabled = value }) }
  message(text) { this.statusTarget.textContent = text; this.statusTarget.hidden = !text }
  unavailable() { this.ready = false; this.tokenTarget.value = ""; this.setDisabled(false); this.message("Verification is unavailable. Submit to check again or try shortly.") }
}

application.register("add-auth-challenge", ChallengeController)
