export function decode(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new TypeError("Invalid encoding")
  const text = atob(value.replace(/-/g, "+").replace(/_/g, "/"))
  return Uint8Array.from(text, character => character.charCodeAt(0))
}
export function encode(value) {
  return btoa(Array.from(new Uint8Array(value), byte => String.fromCharCode(byte)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}
export function options(json, create) {
  const native = create ? PublicKeyCredential.parseCreationOptionsFromJSON : PublicKeyCredential.parseRequestOptionsFromJSON
  if (native) return native.call(PublicKeyCredential, json)
  const value = { ...json, challenge: decode(json.challenge) }
  if (create) value.user = { ...json.user, id: decode(json.user.id) }
  for (const key of ["allowCredentials", "excludeCredentials"]) {
    if (json[key]) value[key] = json[key].map(item => ({ ...item, id: decode(item.id) }))
  }
  return value
}
export function credential(value) {
  if (value.toJSON) return value.toJSON()
  const response = { clientDataJSON: encode(value.response.clientDataJSON) }
  for (const key of ["attestationObject", "authenticatorData", "signature", "userHandle"]) {
    if (value.response[key]) response[key] = encode(value.response[key])
  }
  if (value.response.getTransports) response.transports = value.response.getTransports()
  return { id: value.id, rawId: encode(value.rawId), type: value.type, response,
    clientExtensionResults: value.getClientExtensionResults(), authenticatorAttachment: value.authenticatorAttachment }
}
