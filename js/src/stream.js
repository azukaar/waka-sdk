// The one stream to the hub, kept alive. Modelled on Together's GatewayClient:
// a handshake deadline, a watchdog on the hub's keep-alive, a probe when
// something hints the network changed, and backoff with jitter.
//
// The browser's online/offline and visibility events are hints, never a
// verdict: navigator.onLine is wrong often enough to matter. A hint only
// moves a check forward. The stream itself decides whether the hub is there.

/** Base 1 s, doubling, capped at 30 s, +/-20%, reset after 60 s connected. */
export const defaultBackoff = { baseMs: 1000, factor: 2, capMs: 30000, jitter: 0.2, stableResetAfterMs: 60000 }

const MAX_EVENT_BYTES = 64 * 1024
/** A dial this old with no hello is abandoned when the network is said to be back. */
const STALE_DIAL_MS = 2000

/**
 * @typedef {'disconnected' | 'connecting' | 'connected' | 'reconnecting'} ConnectionState
 */

export class HubStream {
  #o
  #backoff
  #state = 'disconnected'
  #want = false
  #attempt = 0
  #everConnected = false
  /** The current dial. Anything holding an older one has been superseded. */
  #dial = null
  #dialAt = 0
  #streamId = null
  #keepaliveMs = 25000
  #lastByteAt = 0
  #lastTickAt = 0
  #timers = { reconnect: null, handshake: null, watchdog: null, probe: null, stability: null }

  /**
   * @param {object} o
   * @param {string} o.url the events endpoint
   * @param {(streamId: string) => string} o.pingUrl
   * @param {typeof fetch} o.fetch
   * @param {() => Promise<string>} o.token throws when signed out
   * @param {(event: string, data: string) => void} o.onEvent
   * @param {(state: ConnectionState) => void} o.onState
   * @param {() => void} o.onReady every time the stream is established
   * @param {(token: string) => void} o.onUnauthorized the hub refused the session
   * @param {Partial<typeof defaultBackoff>} [o.backoff]
   * @param {number} [o.handshakeTimeoutMs] from dialling to the hub's hello
   * @param {number} [o.probeTimeoutMs]
   * @param {() => number} [o.random]
   * @param {() => number} [o.now] the clock, for tests
   */
  constructor(o) {
    this.#o = { handshakeTimeoutMs: 10000, probeTimeoutMs: 10000, random: Math.random, now: () => Date.now(), ...o }
    this.#backoff = { ...defaultBackoff, ...o.backoff }
  }

  /** @returns {ConnectionState} */
  get state() { return this.#state }

  start() {
    if (this.#want) return
    this.#want = true
    this.#attempt = 0
    this.#everConnected = false
    globalThis.addEventListener?.('online', this.#onOnline)
    globalThis.addEventListener?.('offline', this.#onOffline)
    globalThis.document?.addEventListener?.('visibilitychange', this.#onVisible)
    this.#open()
  }

  /** Drops the stream and stops redialling. start() brings it back. */
  stop() {
    this.#want = false
    globalThis.removeEventListener?.('online', this.#onOnline)
    globalThis.removeEventListener?.('offline', this.#onOffline)
    globalThis.document?.removeEventListener?.('visibilitychange', this.#onVisible)
    this.#teardown()
    this.#setState('disconnected')
  }

  #onOnline = () => this.hint(true)
  #onOffline = () => this.hint(false)
  // Coming back to the foreground is when a phone's stream turns out to have
  // died in the background, and when somebody is looking.
  #onVisible = () => { if (globalThis.document.visibilityState === 'visible') this.hint(true) }

  /**
   * Something suggests the network changed. A live stream is asked to prove
   * itself; a wait between retries is cut short.
   * @param {boolean} [online] false when the hint is that the network went away
   */
  hint(online = true) {
    if (!this.#want) return
    if (this.#state === 'connected') {
      this.#probe()
    } else if (online && (this.#timers.reconnect || this.#o.now() - this.#dialAt > STALE_DIAL_MS)) {
      // Waiting out a backoff the change has probably made moot, or a dial
      // that set out on the network that just went away.
      this.#attempt = 0
      this.#open()
    }
  }

  #open() {
    if (!this.#want) return
    this.#teardown()
    this.#setState(this.#everConnected || this.#attempt > 0 ? 'reconnecting' : 'connecting')
    const dial = new AbortController()
    this.#dial = dial
    this.#dialAt = this.#o.now()
    // A request stuck on a network that changed underneath it reports nothing
    // for minutes, and nothing else would retry it.
    this.#timers.handshake = setTimeout(() => this.#dead(), this.#o.handshakeTimeoutMs)
    this.#read(dial)
  }

  async #read(dial) {
    const current = () => this.#dial === dial
    try {
      let token
      try {
        token = await this.#o.token()
      } catch {
        if (current()) this.stop()
        return
      }
      const res = await this.#o.fetch(this.#o.url, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
        signal: dial.signal,
      })
      if (!current()) return
      if (res.status === 401) {
        this.stop()
        this.#o.onUnauthorized(token)
        return
      }
      // A captive portal or a failing proxy answers 200 with a page.
      const type = res.headers.get('content-type') || ''
      if (!res.ok || !type.startsWith('text/event-stream') || !res.body) throw new Error('not an event stream')

      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
      let buffer = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (!current()) return
        if (done) break
        this.#lastByteAt = this.#o.now()
        buffer = (buffer + value).replace(/\r\n?/g, '\n')
        let end
        while ((end = buffer.indexOf('\n\n')) >= 0) {
          const block = buffer.slice(0, end)
          buffer = buffer.slice(end + 2)
          this.#onBlock(block)
          if (!current()) return
        }
        if (buffer.length > MAX_EVENT_BYTES) throw new Error('event too large')
      }
    } catch {
      // Redial below.
    }
    if (current()) this.#dead()
  }

  #onBlock(block) {
    let event = 'message'
    const data = []
    for (const line of block.split('\n')) {
      if (!line || line[0] === ':') continue
      const colon = line.indexOf(':')
      const field = colon < 0 ? line : line.slice(0, colon)
      const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '')
      if (field === 'event') event = value
      else if (field === 'data') data.push(value)
    }
    if (!data.length) return
    const payload = data.join('\n')
    if (event === 'hello') {
      let hello = {}
      try { hello = JSON.parse(payload) } catch { /* defaults */ }
      this.#ready(hello)
    } else if (event === 'pong') {
      this.#clear('probe')
    } else if (this.#state === 'connected') {
      this.#o.onEvent(event, payload)
    }
  }

  // The hub's hello is the moment the stream exists: headers alone do not
  // prove that events will get through whatever sits in between.
  #ready({ stream, keepalive_ms: keepaliveMs }) {
    this.#clear('handshake')
    this.#streamId = stream || null
    if (keepaliveMs > 0) this.#keepaliveMs = keepaliveMs
    this.#everConnected = true
    this.#setState('connected')
    // A connection that drops straight away must not reset the curve.
    this.#clear('stability')
    this.#timers.stability = setTimeout(() => { this.#attempt = 0 }, this.#backoff.stableResetAfterMs)

    const every = Math.max(this.#keepaliveMs / 2, 10)
    this.#lastTickAt = this.#o.now()
    clearInterval(this.#timers.watchdog)
    this.#timers.watchdog = setInterval(() => this.#tick(every), every)
    this.#o.onReady()
  }

  #tick(every) {
    const at = this.#o.now()
    // A tick far later than scheduled means the device slept and the stream
    // probably went with it. Ask now.
    const slept = at - this.#lastTickAt > every * 4
    this.#lastTickAt = at
    if (slept) {
      this.#probe()
    } else if (at - this.#lastByteAt > this.#keepaliveMs * 2 && !this.#timers.probe) {
      // Two keep-alives missed: the network dropped the stream without saying.
      this.#dead()
    }
  }

  /**
   * Asks the hub for a pong on this stream, with a short deadline. A pong
   * clears it; silence is a dead stream.
   */
  #probe() {
    if (this.#state !== 'connected' || this.#timers.probe) return
    const dial = this.#dial
    if (!this.#streamId) {
      this.#dead()
      return
    }
    this.#timers.probe = setTimeout(() => {
      this.#timers.probe = null
      this.#dead()
    }, this.#o.probeTimeoutMs)
    ;(async () => {
      try {
        const res = await this.#o.fetch(this.#o.pingUrl(this.#streamId), {
          method: 'POST',
          headers: { Authorization: `Bearer ${await this.#o.token()}` },
          signal: dial.signal,
        })
        // The hub is there and does not know this stream (or this session).
        if (this.#dial === dial && (res.status === 404 || res.status === 401)) this.#dead()
      } catch {
        // The request could not leave, which says nothing about the stream:
        // a browser that believes it is offline refuses new requests while
        // old connections still work. Leave it to the watchdog.
        if (this.#dial === dial) this.#clear('probe')
      }
    })()
  }

  #dead() {
    if (!this.#want) return
    this.#teardown()
    this.#setState('reconnecting')
    const raw = this.#backoff.baseMs * Math.pow(this.#backoff.factor, this.#attempt)
    const capped = Math.min(raw, this.#backoff.capMs)
    const jitter = 1 + (this.#o.random() * 2 - 1) * this.#backoff.jitter
    const delay = Math.max(0, Math.min(Math.round(capped * jitter), this.#backoff.capMs))
    this.#attempt++
    this.#timers.reconnect = setTimeout(() => this.#open(), delay)
  }

  #teardown() {
    for (const name of Object.keys(this.#timers)) this.#clear(name)
    const dial = this.#dial
    this.#dial = null
    this.#streamId = null
    dial?.abort()
  }

  #clear(name) {
    clearTimeout(this.#timers[name])
    clearInterval(this.#timers[name])
    this.#timers[name] = null
  }

  #setState(next) {
    if (this.#state === next) return
    this.#state = next
    this.#o.onState(next)
  }
}
