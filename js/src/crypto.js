// Device keys and notification decryption. The matching Go code is in
// waka/seal.go; the blob layout is documented there.

const subtle = globalThis.crypto.subtle
const ECDH = { name: 'ECDH', namedCurve: 'P-256' }
const SEAL_INFO = new TextEncoder().encode('waka-seal-v1')
const PUB_LEN = 65
const NONCE_LEN = 12

export function toBase64(bytes) {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s)
}

export function fromBase64(text) {
  const s = atob(text)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function randomToken(bytes = 32) {
  return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(bytes)))
}

export async function sha256Base64Url(text) {
  return toBase64Url(await subtle.digest('SHA-256', new TextEncoder().encode(text)))
}

/**
 * Creates this device's key pair. The private key is not extractable: it can
 * be stored (IndexedDB keeps CryptoKey objects) but never read out.
 * @returns {Promise<CryptoKeyPair>}
 */
export function generateDeviceKey() {
  return subtle.generateKey(ECDH, false, ['deriveBits'])
}

/** @returns {Promise<Uint8Array>} the raw public key the hub hands to senders */
export async function exportPublicKey(keyPair) {
  return new Uint8Array(await subtle.exportKey('raw', keyPair.publicKey))
}

/**
 * Opens a blob a server sealed to this device.
 * @param {CryptoKeyPair} keyPair
 * @param {string} blob base64
 * @returns {Promise<any>} the decoded JSON payload
 */
export async function openSealed(keyPair, blob) {
  const data = fromBase64(blob)
  if (data.length < 1 + PUB_LEN + NONCE_LEN || data[0] !== 1) throw new Error('not a sealed blob')
  const ephPub = data.slice(1, 1 + PUB_LEN)
  const nonce = data.slice(1 + PUB_LEN, 1 + PUB_LEN + NONCE_LEN)
  const ciphertext = data.slice(1 + PUB_LEN + NONCE_LEN)

  const ephKey = await subtle.importKey('raw', ephPub, ECDH, false, [])
  const shared = await subtle.deriveBits({ name: 'ECDH', public: ephKey }, keyPair.privateKey, 256)
  const salt = new Uint8Array(PUB_LEN * 2)
  salt.set(ephPub, 0)
  salt.set(await exportPublicKey(keyPair), PUB_LEN)
  const hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: SEAL_INFO },
    hkdf, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  )
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext)
  return JSON.parse(new TextDecoder().decode(plain))
}
