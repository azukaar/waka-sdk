// Waka client SDK. Logic only: an app wires it to its own UI.
//
//   const waka = new WakaClient({ hubUrl, redirectUri })
//   await waka.handleRedirect() || await waka.loginRedirect()   // one prompt per device
//   for (const s of await waka.directory()) {
//     const notebooks = await waka.server(s).joined()            // no prompt
//   }

import {
  exportPublicKey, generateDeviceKey, openSealed, randomToken, sha256Base64Url, toBase64,
} from './crypto.js'
import { BrowserStorage, MemoryStorage } from './storage.js'
import { HubStream, defaultBackoff } from './stream.js'

export { BrowserStorage, MemoryStorage, defaultBackoff }

export class WakaError extends Error {
  /**
   * @param {string} message
   * @param {number} status HTTP status. 0 when there was no usable answer:
   *   unreachable, timed out, or something other than the hub or server replied.
   */
  constructor(message, status = 0, cause) {
    super(message, cause ? { cause } : undefined)
    this.name = 'WakaError'
    this.status = status
  }
}

async function parse(res) {
  if (res.status === 204) return null
  const body = await res.json().catch(() => undefined)
  if (!res.ok) throw new WakaError(body?.error_description || body?.error || `request failed (${res.status})`, res.status)
  // A captive portal answers 200 with a page. That is not an answer.
  if (body === undefined) throw new WakaError('unexpected response', 0)
  return body
}

// One JSON call with a deadline that covers the body too. Every failure is a
// WakaError; status 0 means nothing usable came back.
async function send(fetch, url, init, timeoutMs) {
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), timeoutMs)
  try {
    return await parse(await fetch(url, { ...init, signal: abort.signal }))
  } catch (err) {
    if (err instanceof WakaError) throw err
    throw new WakaError(abort.signal.aborted ? 'timed out' : 'could not connect', 0, err)
  } finally {
    clearTimeout(timer)
  }
}

// What a reverse proxy or tunnel answers when the server behind it is down.
const GATEWAY_DOWN = new Set([502, 503, 504])

const trimSlash = (s) => s.replace(/\/+$/, '')

/**
 * @typedef {{ id: string, name: string, address: string, app: string }} Server
 * @typedef {{ type: string, id: string }} Resource
 */

export class WakaClient {
  #fetch
  #storage
  #servers = new Map()
  #timeoutMs
  #stream
  #ended = null

  /**
   * @param {object} opts
   * @param {string} opts.hubUrl
   * @param {string} [opts.redirectUri] where the hub sends the browser back; must be registered on the hub
   * @param {object} [opts.storage] defaults to IndexedDB
   * @param {typeof fetch} [opts.fetch]
   * @param {string} [opts.deviceName] shown in the user's device list
   * @param {number} [opts.requestTimeoutMs] deadline for each hub and sign-in call, 15 s by default
   * @param {object} [opts.connection] timing of the hub stream: backoff, handshakeTimeoutMs, probeTimeoutMs, random
   */
  constructor({ hubUrl, redirectUri, storage, fetch, deviceName, requestTimeoutMs = 15000, connection }) {
    this.hubUrl = trimSlash(hubUrl)
    this.redirectUri = redirectUri
    this.deviceName = deviceName || globalThis.navigator?.userAgent?.slice(0, 64) || 'device'
    this.#storage = storage || new BrowserStorage()
    this.#fetch = fetch || globalThis.fetch.bind(globalThis)
    this.#timeoutMs = requestTimeoutMs
    this.#stream = new HubStream({
      ...connection,
      url: `${this.hubUrl}/api/events`,
      pingUrl: (id) => `${this.hubUrl}/api/events/${encodeURIComponent(id)}/ping`,
      fetch: this.#fetch,
      token: () => this.#token(),
      onState: (state) => this.#emit('state', state),
      onEvent: (event, data) => {
        if (event === 'inbox') this.#emit('inbox', data)
        else if (event === 'hint') this.#drainHints()
      },
      // Whatever happened while the stream was away was not announced.
      onReady: () => {
        this.#emit('inbox', null)
        this.#drainHints()
      },
      onUnauthorized: (token) => this.#sessionEnded(token),
    })
  }

  // --- login ---

  /**
   * Starts a login and returns the URL to open in a browser. This is the
   * only prompt a device ever shows.
   * @param {{ prompt?: 'login', loginHint?: string }} [opts]
   */
  async beginLogin({ prompt, loginHint } = {}) {
    const state = randomToken(16)
    const verifier = randomToken(32)
    await this.#storage.set('login', { state, verifier })
    const q = new URLSearchParams({
      mode: 'session',
      redirect_uri: this.redirectUri,
      state,
      code_challenge: await sha256Base64Url(verifier),
    })
    if (prompt) q.set('prompt', prompt)
    if (loginHint) q.set('login_hint', loginHint)
    return `${this.hubUrl}/auth/start?${q}`
  }

  /** Browser shortcut: navigate to the hub to sign in. */
  async loginRedirect(opts) {
    globalThis.location.assign(await this.beginLogin(opts))
  }

  /**
   * Finishes a login from the URL the hub redirected back to.
   * @param {string} callbackUrl
   * @returns {Promise<object|null>} the user, or null if the URL is not a login callback
   */
  async completeLogin(callbackUrl) {
    const params = new URL(callbackUrl).searchParams
    const pending = await this.#storage.get('login')
    if (!params.get('state') || !pending || params.get('state') !== pending.state) return null
    await this.#storage.delete('login')
    if (params.get('error')) throw new WakaError(`login was not completed: ${params.get('error')}`)

    const res = await send(this.#fetch, `${this.hubUrl}/auth/redeem`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: params.get('code'), code_verifier: pending.verifier }),
    }, this.#timeoutMs)
    await this.#storage.set('session', { token: res.token, expiresAt: res.expires_at })
    await this.#registerDevice()
    this.#syncStream()
    return res.user
  }

  /** Browser shortcut: finish a login if the page was opened by the hub's redirect. */
  async handleRedirect() {
    const user = await this.completeLogin(globalThis.location.href)
    if (user) {
      const url = new URL(globalThis.location.href)
      for (const k of ['code', 'state', 'error']) url.searchParams.delete(k)
      globalThis.history.replaceState(null, '', url)
    }
    return user
  }

  async isLoggedIn() {
    const s = await this.#storage.get('session')
    return !!s && s.expiresAt * 1000 > Date.now()
  }

  /** Signs this device out of the hub and forgets every server session. */
  async logout() {
    await this.#hub('POST', '/api/session/logout').catch(() => {})
    await this.#forget()
  }

  async #forget() {
    this.#stream.stop()
    for (const s of this.#servers.values()) await s.forget()
    this.#servers.clear()
    for (const id of (await this.#storage.get('serverIds')) || []) await this.#storage.delete(`server:${id}`)
    for (const k of ['session', 'deviceId', 'serverIds', 'directory']) await this.#storage.delete(k)
  }

  // The hub session is only ever sent to the hub, never to a server.
  async #token() {
    const s = await this.#storage.get('session')
    if (!s) throw new WakaError('not signed in', 401)
    return s.token
  }

  async #hub(method, path, body, raw) {
    const token = await this.#token()
    const headers = { Authorization: `Bearer ${token}` }
    let payload
    if (raw) {
      payload = raw
    } else if (body !== undefined) {
      headers['Content-Type'] = 'application/json'
      payload = JSON.stringify(body)
    }
    try {
      return await send(this.#fetch, this.hubUrl + path, { method, headers, body: payload }, this.#timeoutMs)
    } catch (err) {
      if (err.status === 401) await this.#sessionEnded(token)
      throw err
    }
  }

  // The hub refused a session. Only the current one is forgotten: a late
  // answer to a call made before signing in again must not undo the new login.
  async #sessionEnded(token) {
    const s = await this.#storage.get('session')
    // Several calls can be refused at once; the session ends once.
    if (!s || s.token !== token || this.#ended === token) return
    this.#ended = token
    await this.#forget()
    this.#emit('ended')
  }

  /**
   * Calls back when the hub ends this device's session (signed out from
   * another device, or the account is gone). Not called by logout().
   * @param {() => void} fn
   * @returns {() => void} stop
   */
  onSessionEnded(fn) {
    this.#listeners.ended.add(fn)
    return () => this.#listeners.ended.delete(fn)
  }

  // --- device keys ---

  // One sealing key per server, made on the first token exchange to it and
  // registered with the hub then. A server only ever sees its own key for
  // this device, so two servers cannot tell they reach the same device.
  async #serverKey(serverId) {
    let key = await this.#storage.get(`deviceKey:${serverId}`)
    if (!key) {
      key = await generateDeviceKey()
      await this.#storage.set(`deviceKey:${serverId}`, key)
    }
    return key
  }

  // The public half as the hub takes it, kept so a renewal costs no crypto.
  #publicKeys = new Map()

  async #publicKey(serverId) {
    if (!this.#publicKeys.has(serverId)) {
      this.#publicKeys.set(serverId, toBase64(await exportPublicKey(await this.#serverKey(serverId))))
    }
    return this.#publicKeys.get(serverId)
  }

  // What a server sealed to this device, opened with the key made for that
  // server. Null when there is none, or no key for that server.
  async #open(serverId, blob) {
    const key = blob && serverId && (await this.#storage.get(`deviceKey:${serverId}`))
    return key ? openSealed(key, blob).catch(() => null) : null
  }

  async #registerDevice() {
    const { id } = await this.#hub('POST', '/api/devices', { name: this.deviceName })
    await this.#storage.set('deviceId', id)
  }

  devices() { return this.#hub('GET', '/api/devices') }
  /** Removes a device and signs it out. */
  removeDevice(id) { return this.#hub('DELETE', `/api/devices/${encodeURIComponent(id)}`) }

  // --- profile ---

  /** The account's profile in this app. The session belongs to one app. */
  me() { return this.#hub('GET', '/api/me') }

  /**
   * Edits the app profile. Server sessions are renewed straight away so
   * every server picks the change up instead of waiting for expiry.
   * @param {{ handle?: string, name?: string, bio?: string }} changes
   */
  async updateProfile(changes) {
    const user = await this.#hub('PATCH', '/api/me', changes)
    await this.#renewAll()
    return user
  }

  /** @param {Blob|ArrayBuffer|Uint8Array} image PNG, JPEG, GIF or WebP, at most 512 KB */
  async setAvatar(image) {
    const user = await this.#hub('PUT', '/api/me/avatar', undefined, image)
    await this.#renewAll()
    return user
  }

  async removeAvatar() {
    await this.#hub('DELETE', '/api/me/avatar')
    await this.#renewAll()
  }

  /**
   * What the account shows one server: `override` (each field null where the
   * app profile applies) and the resulting `profile`.
   * @param {string} serverId
   */
  serverProfile(serverId) { return this.#hub('GET', `/api/me/servers/${encodeURIComponent(serverId)}`) }

  /**
   * Overrides the profile for one server. A field left out is unchanged, null
   * goes back to the app profile. That server's session is renewed at once.
   * @param {string} serverId
   * @param {{ handle?: string|null, name?: string|null, bio?: string|null }} changes
   */
  async updateServerProfile(serverId, changes) {
    const res = await this.#hub('PATCH', `/api/me/servers/${encodeURIComponent(serverId)}`, changes)
    await this.#renewOne(serverId)
    return res
  }

  /** Drops every override for one server, avatar included. */
  async clearServerProfile(serverId) {
    await this.#hub('DELETE', `/api/me/servers/${encodeURIComponent(serverId)}`)
    await this.#renewOne(serverId)
  }

  /** @param {string} serverId @param {Blob|ArrayBuffer|Uint8Array} image */
  async setServerAvatar(serverId, image) {
    const res = await this.#hub('PUT', `/api/me/servers/${encodeURIComponent(serverId)}/avatar`, undefined, image)
    await this.#renewOne(serverId)
    return res
  }

  async removeServerAvatar(serverId) {
    await this.#hub('DELETE', `/api/me/servers/${encodeURIComponent(serverId)}/avatar`)
    await this.#renewOne(serverId)
  }

  async #renewAll() {
    await Promise.allSettled([...this.#servers.values()].map((s) => s.renew()))
  }

  async #renewOne(serverId) {
    await this.#servers.get(serverId)?.renew().catch(() => {})
  }

  /**
   * Finds an account of this app by exact handle. There is no search, and no
   * lookup by email. Without `server`, only app handles match and the answer
   * is the app profile. With it, the handle is resolved as that server sees
   * it (an override handle there, the app handle otherwise) and the answer is
   * the person's profile on that server: use this before sharing there.
   * @param {string} handle
   * @param {{ server?: string | { id: string } }} [opts]
   * @returns {Promise<{ handle: string, name: string, picture: string }>}
   */
  lookupUser(handle, { server } = {}) {
    const q = new URLSearchParams({ q: handle })
    if (server) q.set('server', typeof server === 'string' ? server : server.id)
    return this.#hub('GET', `/api/users/lookup?${q}`)
  }

  // --- directory ---

  /** The last directory() answer, without asking the hub. Null if there is none. */
  async cachedDirectory() { return (await this.#storage.get('directory')) || null }

  /**
   * The servers this account uses, on any device. The last answer is kept, so
   * the list (and the stored server sessions) still work while the hub is down.
   * @returns {Promise<Server[]>}
   */
  async directory() {
    try {
      const servers = await this.#hub('GET', '/api/directory')
      await this.#storage.set('directory', servers)
      return servers
    } catch (err) {
      const cached = await this.#storage.get('directory')
      // A refusal is an answer; only an unreachable or failing hub falls back.
      if (!cached || (err.status && err.status < 500)) throw err
      return cached
    }
  }

  /**
   * Adds a server by its address. This is the consent step for that server.
   * A server nobody owns yet is claimed on the way: registered on the hub
   * under this account, which makes it the owner, and handed its credentials.
   * @returns {Promise<Server>}
   */
  async addServer(address) {
    address = trimSlash(address)
    const info = await send(this.#fetch, `${address}/.well-known/waka-server`, {}, this.#timeoutMs)
    if (trimSlash(info.issuer) !== this.hubUrl) {
      throw new WakaError(`that server uses another hub (${info.issuer})`)
    }
    const serverId = info.claimed === false ? await this.#claim(address, info) : info.server_id
    const server = await this.#hub('PUT', `/api/directory/${encodeURIComponent(serverId)}`)
    await this.#recache((list) => [...list.filter((s) => s.id !== server.id), server])
    return server
  }

  // Registers an unclaimed server under this account and hands it the
  // credentials. If the server refuses them (someone else got there first),
  // the registration is withdrawn so it does not linger on the account.
  async #claim(address, info) {
    const reg = await this.registerServer({ name: info.name || new URL(address).host, address })
    try {
      await send(this.#fetch, `${address}/waka/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: reg.id, secret: reg.secret }),
      }, this.#timeoutMs)
    } catch (err) {
      await this.deleteServer(reg.id).catch(() => {})
      throw err
    }
    return reg.id
  }

  async removeServer(id) {
    const res = await this.#hub('DELETE', `/api/directory/${encodeURIComponent(id)}`)
    await this.#recache((list) => list.filter((s) => s.id !== id))
    return res
  }

  // Keeps the stored directory in step with a change, so it is right even if
  // the hub goes away before directory() is called again.
  async #recache(change) {
    const cached = await this.#storage.get('directory')
    if (cached) await this.#storage.set('directory', change(cached))
  }

  /**
   * Registers a server you run, for this app; you own it. The secret is
   * returned once, for its config file.
   */
  registerServer({ name, address }) { return this.#hub('POST', '/api/servers', { name, address }) }
  myServers() { return this.#hub('GET', '/api/servers') }
  deleteServer(id) { return this.#hub('DELETE', `/api/servers/${encodeURIComponent(id)}`) }

  /**
   * A connection to one server. Signing in to it is silent.
   * @param {Server} server an entry from directory() or an inbox item's from_server
   * @returns {ServerConnection}
   */
  server(server) {
    let conn = this.#servers.get(server.id)
    if (!conn || conn.address !== trimSlash(server.address)) {
      conn = new ServerConnection(server, {
        fetch: this.#fetch,
        storage: this.#storage,
        timeoutMs: this.#timeoutMs,
        exchange: () => this.#exchange(server.id),
      })
      this.#servers.set(server.id, conn)
    }
    return conn
  }

  // Standard token exchange: the hub session in, a token for one server out.
  // It also registers this device's sealing key for that server.
  async #exchange(serverId) {
    const deviceKey = await this.#publicKey(serverId)
    const res = await send(this.#fetch, `${this.hubUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: await this.#token(),
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        audience: serverId,
        device_key: deviceKey,
      }),
    }, this.#timeoutMs)
    const ids = new Set((await this.#storage.get('serverIds')) || [])
    if (!ids.has(serverId)) await this.#storage.set('serverIds', [...ids.add(serverId)])
    return res.access_token
  }

  // --- inbox ---

  /**
   * Lists the inbox. Each item gets a decrypted `body`, or null when this
   * device had no key for the sending server yet: it was sent before the
   * device signed in to that server (use inviteDetails for those).
   * @param {{ status?: string }} [opts]
   */
  async inbox({ status } = {}) {
    const items = await this.#hub('GET', `/api/inbox${status ? `?status=${status}` : ''}`)
    for (const item of items) {
      item.body = await this.#open(item.from_server?.id, item.blob)
      delete item.blob
    }
    return items
  }

  /** Reads an invite's details from the server that sent it. */
  async inviteDetails(item) {
    const invites = await this.server(item.from_server).invites()
    return invites.find((g) => g.id === item.ref) || null
  }

  /**
   * Accepts a share: joins on the server that sent it, then marks the invite
   * accepted on the hub, which adds that server to the directory.
   */
  async acceptInvite(item) {
    await this.server(item.from_server).acceptGrant(item.ref)
    const res = await this.#hub('POST', `/api/inbox/${item.id}/accept`)
    await this.#recache((list) => (list.some((s) => s.id === item.from_server.id) ? list : [...list, item.from_server]))
    return res
  }

  /**
   * Reads what a link leads to, without signing in to its server: the card
   * to show before joining. See previewLink.
   * @param {string} url
   * @param {{ password?: string }} [opts]
   */
  previewLink(url, { password } = {}) {
    return previewLink(url, { password, fetch: this.#fetch, timeoutMs: this.#timeoutMs })
  }

  /**
   * Joins through a link with this account: adds the link's server to the
   * directory (the consent step for that server), signs in there and claims
   * the link, in one go. It works on a server that only lets in people with
   * a grant. If it fails, a server that was not in the directory is taken
   * out again.
   * @param {string} url
   * @param {{ password?: string }} [opts]
   * @returns {Promise<{ server: Server, grant: object }>}
   */
  async joinLink(url, { password } = {}) {
    const { address } = parseLink(url)
    const info = await send(this.#fetch, `${address}/.well-known/waka-server`, {}, this.#timeoutMs)
    if (trimSlash(info.issuer) !== this.hubUrl) {
      throw new WakaError(`that server uses another hub (${info.issuer})`)
    }
    const known = (await this.directory()).some((s) => s.id === info.server_id)
    const server = await this.#hub('PUT', `/api/directory/${encodeURIComponent(info.server_id)}`)
    try {
      const grant = await this.server(server).joinLink(url, { password })
      await this.#recache((list) => (list.some((s) => s.id === server.id) ? list : [...list, server]))
      return { server, grant }
    } catch (err) {
      if (!known) await this.#hub('DELETE', `/api/directory/${encodeURIComponent(server.id)}`).catch(() => {})
      throw err
    }
  }

  /** Declines on the hub only: the sending server never hears from this device. */
  declineInvite(item) { return this.#hub('POST', `/api/inbox/${item.id}/decline`) }
  markRead(item) { return this.#hub('POST', `/api/inbox/${item.id}/read`) }
  deleteInboxItem(item) { return this.#hub('DELETE', `/api/inbox/${item.id}`) }

  /** Blocks in this app, each with the person as they appeared where they were blocked. */
  blocks() { return this.#hub('GET', '/api/blocks') }
  /** Blocks whoever sent an inbox item, in this app. Their invites stop arriving. */
  blockSender(item) { return this.#hub('POST', `/api/inbox/${item.id}/block`) }
  /** @param {string} blockId an id from blocks() */
  unblock(blockId) { return this.#hub('DELETE', `/api/blocks/${encodeURIComponent(blockId)}`) }

  /**
   * Calls back with the ID of whatever lands in the inbox, and with null each
   * time the hub stream is (re)established: anything may have arrived while it
   * was away, so that is the moment to list the inbox again.
   * @param {(itemId: string | null) => void} onItem
   * @returns {() => void} stop
   */
  subscribe(onItem) { return this.#listen('inbox', onItem) }

  /**
   * Calls back with each hint: a server saying "something changed here".
   * The SDK does nothing else with it. Whether to sync, how, and whether to
   * open a socket is the app's decision.
   *
   * Hints waiting from before are delivered first, and again whenever the
   * stream comes back. A hint is dropped once every listener has returned (or
   * its promise resolved); if one throws, the hint stays and is delivered
   * again later. Hints are best effort and can arrive twice: an app must
   * still sync when it opens.
   * @param {(hint: { id: string, server: Server, key: string, body: any }) => void | Promise<void>} onHint
   * @returns {() => void} stop
   */
  onHint(onHint) {
    const stop = this.#listen('hint', onHint)
    this.#drainHints()
    return stop
  }

  #draining = null
  #drainAgain = false

  #drainHints() {
    if (!this.#listeners.hint.size) return
    if (this.#draining) {
      this.#drainAgain = true
      return
    }
    this.#draining = (async () => {
      do {
        this.#drainAgain = false
        for (const h of await this.#hub('GET', '/api/hints')) {
          const listeners = [...this.#listeners.hint]
          if (!listeners.length) return
          const hint = { id: h.id, server: h.from_server, key: h.key, body: await this.#open(h.from_server?.id, h.blob) }
          const results = await Promise.allSettled(listeners.map(async (fn) => fn(hint)))
          if (results.some((r) => r.status === 'rejected')) continue
          await this.#hub('DELETE', `/api/hints/${h.id}`)
        }
      } while (this.#drainAgain)
    })().catch(() => {}).finally(() => { this.#draining = null })
  }

  // --- connection ---

  // One stream to the hub, shared by every listener and open while there is one.
  #listeners = { inbox: new Set(), hint: new Set(), state: new Set(), ended: new Set() }

  #listen(kind, fn) {
    this.#listeners[kind].add(fn)
    this.#syncStream()
    return () => {
      this.#listeners[kind].delete(fn)
      this.#syncStream()
    }
  }

  #syncStream() {
    const l = this.#listeners
    if (l.inbox.size || l.hint.size || l.state.size) this.#stream.start()
    else this.#stream.stop()
  }

  // A listener that throws must not take the stream down with it.
  #emit(kind, ...args) {
    for (const fn of [...this.#listeners[kind]]) {
      try { fn(...args) } catch { /* the listener's problem */ }
    }
  }

  /**
   * The hub stream: "connecting" for the first attempt, "connected",
   * "reconnecting" while it is being retried, "disconnected" when nothing is
   * listening or nobody is signed in.
   * @returns {'disconnected' | 'connecting' | 'connected' | 'reconnecting'}
   */
  get connectionState() { return this.#stream.state }

  /**
   * Calls back on every change of connectionState. Listening keeps the
   * stream open.
   * @param {(state: 'disconnected' | 'connecting' | 'connected' | 'reconnecting') => void} fn
   * @returns {() => void} stop
   */
  onConnectionState(fn) { return this.#listen('state', fn) }

  /**
   * Tells the SDK the network may have changed: a live stream is checked at
   * once and a pending retry happens now. Browsers do this by themselves
   * (online, offline, tab shown); call it from a native shell's own resume
   * and network events.
   * @param {boolean} [online] false if the network seems to have gone away
   */
  checkConnection(online = true) { this.#stream.hint(online) }
}

/**
 * One app server. Its session is fetched silently from the hub session and
 * renewed before it runs out; servers themselves never call the hub.
 */
export class ServerConnection {
  #fetch
  #storage
  #exchange
  #timeoutMs
  #pending = null
  #renewRetryAt = 0
  #reachable = null
  #reachListeners = new Set()

  constructor(server, { fetch, storage, exchange, timeoutMs = 15000 }) {
    this.id = server.id
    this.address = trimSlash(server.address)
    this.name = server.name
    this.#fetch = fetch
    this.#storage = storage
    this.#exchange = exchange
    this.#timeoutMs = timeoutMs
  }

  /**
   * Whether the last call got through to this server: null before any call.
   * A proxy answering for a server that is down (502, 503, 504) counts as not.
   * @returns {boolean | null}
   */
  get reachable() { return this.#reachable }

  /**
   * Calls back when reachable changes.
   * @param {(reachable: boolean) => void} fn
   * @returns {() => void} stop
   */
  onReachable(fn) {
    this.#reachListeners.add(fn)
    return () => this.#reachListeners.delete(fn)
  }

  #mark(reachable) {
    if (this.#reachable === reachable) return
    this.#reachable = reachable
    for (const fn of [...this.#reachListeners]) {
      try { fn(reachable) } catch { /* the listener's problem */ }
    }
  }

  /** Asks the server whether it is there. Needs no session. */
  async check() {
    try {
      await send(this.#fetch, `${this.address}/.well-known/waka-server`, {}, this.#timeoutMs)
      this.#mark(true)
    } catch (err) {
      this.#mark(err.status > 0 && !GATEWAY_DOWN.has(err.status))
    }
    return this.#reachable
  }

  get #key() { return `server:${this.id}` }

  /** Drops the stored session for this server. */
  forget() { return this.#storage.delete(this.#key) }

  /** Gets a fresh hub token and a fresh session from the server. */
  renew() {
    this.#pending ||= (async () => {
      try {
        const token = await this.#exchange()
        const res = await send(this.#fetch, `${this.address}/waka/session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        }, this.#timeoutMs).then(
          (ok) => { this.#mark(true); return ok },
          (err) => { this.#mark(err.status > 0 && !GATEWAY_DOWN.has(err.status)); throw err },
        )
        const session = { token: res.session, expiresAt: res.expires_at, issuedAt: Math.floor(Date.now() / 1000), user: res.user }
        await this.#storage.set(this.#key, session)
        return session
      } finally {
        this.#pending = null
      }
    })()
    return this.#pending
  }

  async #session() {
    const s = await this.#storage.get(this.#key)
    const nowSec = Date.now() / 1000
    if (!s || s.expiresAt <= nowSec) return this.renew()
    // Past half its life: renew behind the call rather than in front of it,
    // so a hub that is down or slow costs nothing here.
    if (nowSec > (s.issuedAt + s.expiresAt) / 2 && Date.now() >= this.#renewRetryAt) {
      this.#renewRetryAt = Date.now() + 60000
      this.renew().catch(() => {})
    }
    return s
  }

  /** The user as this server knows them (its own copy of the profile). */
  async user() { return (await this.#session()).user }

  /**
   * The current session on this server, as a string, renewed first if it
   * ran out. For protocols that carry it in a message rather than a header:
   * a socket's identify message, a Hocuspocus token. The server checks it
   * with SessionPrincipal.
   * @returns {Promise<string>}
   */
  async session() { return (await this.#session()).token }

  /**
   * Joins through a link with the hub login instead of a session here, so it
   * works where this account cannot sign in yet. Stores the session the
   * server answers with. WakaClient.joinLink also adds the server to the
   * directory, which the hub needs first.
   * @returns {Promise<object>} the account's grant
   */
  async joinLink(url, { password } = {}) {
    const { id, secret } = parseLink(url)
    const token = await this.#exchange()
    const res = await send(this.#fetch, `${this.address}/waka/links/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, id, secret, password }),
    }, this.#timeoutMs)
    await this.#storage.set(this.#key, { token: res.session, expiresAt: res.expires_at, issuedAt: Math.floor(Date.now() / 1000), user: res.user })
    this.#mark(true)
    return res.grant
  }

  /**
   * fetch against this server with its session attached. Use it for the
   * app's own routes.
   * @param {string} path
   * @param {RequestInit} [init]
   */
  async fetch(path, init = {}) {
    const call = async (s) => {
      let res
      try {
        res = await this.#fetch(this.address + path, {
          ...init, headers: { ...init.headers, Authorization: `Bearer ${s.token}` },
        })
      } catch (err) {
        if (!init.signal?.aborted) this.#mark(false)
        throw err
      }
      this.#mark(!GATEWAY_DOWN.has(res.status))
      return res
    }
    let res = await call(await this.#session())
    if (res.status === 401) res = await call(await this.renew())
    return res
  }

  /** JSON helper over fetch. */
  async request(method, path, body) {
    const init = { method }
    if (body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' }
      init.body = JSON.stringify(body)
    }
    return parse(await this.fetch(path, init))
  }

  // What the user has joined here, and what they could join.
  joined() { return this.request('GET', '/waka/joined') }
  joinable() { return this.request('GET', '/waka/joinable') }
  invites() { return this.request('GET', '/waka/invites') }
  /** @param {Resource} resource */
  join(resource) { return this.request('POST', '/waka/join', resource) }
  acceptGrant(grantId) { return this.request('POST', `/waka/grants/${grantId}/accept`) }
  declineGrant(grantId) { return this.request('POST', `/waka/grants/${grantId}/decline`) }
  leave(grantId) { return this.request('POST', `/waka/grants/${grantId}/leave`) }

  // Sharing.
  /**
   * A resource's roles, which of them this account may hand out (by share,
   * by link for accounts, by public link), what it holds, and whether it may
   * share and manage. Everything a share dialog needs.
   * @param {Resource} resource
   */
  roles(resource) {
    return this.request('GET', `/waka/roles?type=${encodeURIComponent(resource.type)}&id=${encodeURIComponent(resource.id)}`)
  }
  /**
   * Who has access, and links: every link for someone who may manage, their
   * own for someone who may only share. Each says whether it is `editable`.
   * @param {Resource} resource
   */
  grants(resource) {
    return this.request('GET', `/waka/grants?type=${encodeURIComponent(resource.type)}&id=${encodeURIComponent(resource.id)}`)
  }
  /**
   * Shares with a Waka account by the exact handle it has on this server.
   * @param {Resource} resource @param {string} target @param {string | string[]} roles
   */
  share(resource, target, roles) { return this.request('POST', '/waka/grants', { resource, target, roles: [roles].flat() }) }
  /** Replaces the roles of someone's grant or of a link. @param {string | string[]} roles */
  setRoles(grantId, roles) { return this.request('PATCH', `/waka/grants/${grantId}`, { roles: [roles].flat() }) }
  revoke(grantId) { return this.request('DELETE', `/waka/grants/${grantId}`) }
  /**
   * A link for accounts by default; `public: true` for one that works
   * without an account.
   * @param {Resource} resource @param {string | string[]} roles
   * @param {{ public?: boolean, password?: string, expiresAt?: number, maxUses?: number, label?: string }} [opts]
   * @returns {Promise<{ url: string, grant: object }>} the URL is only available now
   */
  createLink(resource, roles, { public: isPublic, password, expiresAt, maxUses, label } = {}) {
    return this.request('POST', '/waka/links', {
      resource, roles: [roles].flat(), public: !!isPublic, password, expires_at: expiresAt, max_uses: maxUses, label,
    })
  }
  /** Turns a link into this account's own grant ("add to my account"). */
  claimLink(url, password) {
    const { id, secret } = parseLink(url)
    return this.request('POST', '/waka/links/claim', { id, secret, password })
  }

  // Server administration.
  me() { return this.request('GET', '/waka/me') }
  bans() { return this.request('GET', '/waka/bans') }
  ban({ userId, handle, reason }) { return this.request('POST', '/waka/bans', { user_id: userId, handle, reason }) }
  unban(userId) { return this.request('DELETE', `/waka/bans/${userId}`) }
}

/** Splits a share link into the server address, the link ID and the secret. */
export function parseLink(url) {
  const u = new URL(url)
  return { address: u.origin, id: u.pathname.split('/').filter(Boolean).pop(), secret: u.hash.slice(1) }
}

/**
 * Reads what a link leads to, with no account and no session: the server,
 * the resource, the roles it gives, who made it, whether it is public, needs
 * a password, or expires. Opening a link should show this and wait for the
 * person to join; nothing is joined by reading it. With a password set on
 * the link, the title and who made it come only with the right password
 * (`locked` until then). Throws 401 for a wrong password, 404 for a dead
 * link, 429 after too many tries.
 * @param {string} url
 * @param {{ password?: string, fetch?: typeof fetch, timeoutMs?: number }} [opts]
 */
export function previewLink(url, { password, fetch = globalThis.fetch.bind(globalThis), timeoutMs = 15000 } = {}) {
  const { address, id, secret } = parseLink(url)
  return send(fetch, `${address}/waka/links/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, secret, password }),
  }, timeoutMs)
}

/**
 * Opens a public link without an account. A link for accounts throws 403;
 * join it with WakaClient.joinLink instead.
 * @param {string} url
 * @param {{ password?: string, fetch?: typeof fetch }} [opts]
 * @returns {Promise<{ resource: Resource, roles: string[], title: string, fetch: (path: string, init?: RequestInit) => Promise<Response> }>}
 */
export async function openLink(url, { password, fetch = globalThis.fetch.bind(globalThis) } = {}) {
  const { address, id, secret } = parseLink(url)
  const link = await send(fetch, `${address}/waka/links/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, secret, password }),
  }, 15000)
  return {
    resource: link.resource,
    roles: link.roles,
    title: link.title,
    fetch: (path, init = {}) => fetch(address + path, {
      ...init, headers: { ...init.headers, Authorization: `Bearer ${link.session}` },
    }),
  }
}
