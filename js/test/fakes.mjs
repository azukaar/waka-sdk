// A network the tests control: every fetch is held until the test answers it.
import { mock } from 'node:test'

export class Call {
  constructor(url, init) {
    this.url = String(url)
    this.init = init
    this.method = init.method || 'GET'
    this.aborted = false
    this.promise = new Promise((resolve, reject) => { this.resolve = resolve; this.reject = reject })
    this.promise.catch(() => {})
    init.signal?.addEventListener('abort', () => {
      this.aborted = true
      const err = new DOMException('This operation was aborted', 'AbortError')
      this.reject(err)
      try { this.controller?.error(err) } catch { /* already closed */ }
    })
  }

  /** Answers with a body the test keeps writing to. */
  open(headers = { 'content-type': 'text/event-stream' }, status = 200) {
    const body = new ReadableStream({ start: (c) => { this.controller = c } })
    this.resolve(new Response(body, { status, headers }))
    return this
  }
  push(text) { this.controller.enqueue(new TextEncoder().encode(text)); return this }
  hello(id = 's1', keepaliveMs = 25000) {
    return this.push(`event: hello\ndata: {"stream":"${id}","keepalive_ms":${keepaliveMs}}\n\n`)
  }
  event(name, data) { return this.push(`event: ${name}\ndata: ${data}\n\n`) }
  keepalive() { return this.push(': ping\n\n') }
  /** The server closes the stream. */
  end() { this.controller.close() }
  /** The connection breaks. */
  cut() { this.controller.error(new TypeError('terminated')) }

  json(body, status = 200) {
    this.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }))
  }
  status(code) { this.resolve(new Response(null, { status: code })) }
  html(status = 200) {
    this.resolve(new Response('<html>Sign in to Wi-Fi</html>', { status, headers: { 'content-type': 'text/html' } }))
  }
  fail() { this.reject(new TypeError('fetch failed')) }
}

export class FakeNet {
  calls = []
  /** Set to answer calls as they arrive: (call) => void. */
  route = null
  fetch = (url, init = {}) => {
    const call = new Call(url, init)
    this.calls.push(call)
    this.route?.(call)
    return call.promise
  }
  to(suffix, method) {
    return this.calls.filter((c) => c.url.endsWith(suffix) && (!method || c.method === method))
  }
  get dials() { return this.to('/api/events') }
  get dial() { return this.dials.at(-1) }
  get pings() { return this.calls.filter((c) => c.url.endsWith('/ping')) }
}

export function fakeClock() {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 1_700_000_000_000 })
}

// Lets promise chains and stream reads settle. setImmediate is not mocked.
export async function flush(turns = 4) {
  for (let i = 0; i < turns; i++) await new Promise((r) => setImmediate(r))
}

// Moves the clock in small steps so code that awaits between timers behaves
// as it would with time really passing.
export async function advance(ms, step = 100) {
  await flush()
  for (let left = ms; left > 0; left -= step) {
    mock.timers.tick(Math.min(step, left))
    await flush(2)
  }
  await flush()
}

// The device sleeps: the wall clock jumps and no timer fires meanwhile. Pass
// `now` to the stream as its clock.
let skew = 0
export const now = () => Date.now() + skew
export function sleep(ms) { skew += ms }
