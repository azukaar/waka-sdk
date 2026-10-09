// What the client does around the stream: status, resync, the session ending,
// timeouts, a hub that is down, and servers that come and go.
import assert from 'node:assert/strict'
import { afterEach, beforeEach, mock, test } from 'node:test'
import { generateDeviceKey } from '../src/crypto.js'
import { MemoryStorage, WakaClient } from '../src/index.js'
import { FakeNet, advance, fakeClock, flush } from './fakes.mjs'

const HUB = 'http://hub'
const FAR = 4_000_000_000
let net, storage, waka, stops

async function client({ signedIn = true } = {}) {
  net = new FakeNet()
  storage = new MemoryStorage()
  if (signedIn) await storage.set('session', { token: 'wkh_one', expiresAt: FAR })
  // Made up front: key generation takes real time, which the fake clock cannot wait for.
  await storage.set('deviceKey:srv', await generateDeviceKey())
  waka = new WakaClient({ hubUrl: HUB, redirectUri: 'http://app/', storage, fetch: net.fetch, connection: { random: () => 0.5 } })
  stops = []
  return waka
}

const listen = (stop) => { stops.push(stop); return stop }

// Answers everything but the stream, which each test drives by hand.
function hub(routes = {}) {
  net.route = (call) => {
    const path = call.url.replace(HUB, '')
    const key = `${call.method} ${path}`
    for (const [pattern, answer] of Object.entries(routes)) {
      if (key === pattern || (pattern.endsWith('*') && key.startsWith(pattern.slice(0, -1)))) return answer(call)
    }
  }
}

async function openStream(id = 's1') {
  await flush()
  net.dial.open().hello(id)
  await flush()
}

beforeEach(() => fakeClock())
afterEach(() => { for (const stop of stops) stop(); mock.timers.reset() })

test('reports the connection state and stops when nobody listens', async () => {
  await client()
  assert.equal(waka.connectionState, 'disconnected')
  const states = []
  const stop = waka.onConnectionState((s) => states.push(s))
  await openStream()
  assert.equal(waka.connectionState, 'connected')
  net.dial.cut()
  await flush()
  assert.equal(waka.connectionState, 'reconnecting')
  await advance(1000)
  await openStream()
  stop()
  assert.equal(waka.connectionState, 'disconnected')
  assert.equal(net.dial.aborted, true)
  assert.deepEqual(states, ['connecting', 'connected', 'reconnecting', 'connected'])
})

test('every listener shares one stream', async () => {
  await client()
  hub({ 'GET /api/hints': (c) => c.json([]) })
  const a = listen(waka.subscribe(() => {}))
  listen(waka.onHint(() => {}))
  listen(waka.onConnectionState(() => {}))
  await openStream()
  assert.equal(net.dials.length, 1)
  a()
  assert.equal(waka.connectionState, 'connected')
})

test('subscribe gets null on every (re)connect and the item ID in between', async () => {
  await client()
  const got = []
  listen(waka.subscribe((id) => got.push(id)))
  await openStream()
  net.dial.event('inbox', 'item1')
  await flush()
  net.dial.cut()
  await advance(1000)
  await openStream('s2')
  assert.deepEqual(got, [null, 'item1', null])
})

test('a listener that throws does not break the stream or the others', async () => {
  await client()
  const got = []
  listen(waka.subscribe(() => { throw new Error('app bug') }))
  listen(waka.subscribe((id) => got.push(id)))
  await openStream()
  net.dial.event('inbox', 'item1')
  await flush()
  assert.deepEqual(got, [null, 'item1'])
  assert.equal(waka.connectionState, 'connected')
})

test('hints are fetched on connect, on a hint event and again after a reconnect', async () => {
  await client()
  let waiting = [{ id: 'h1', key: 'album:1', from_server: { id: 'srv' }, blob: '' }]
  const deleted = []
  hub({
    'GET /api/hints': (c) => c.json(waiting),
    'DELETE /api/hints/*': (c) => { deleted.push(c.url.split('/').pop()); waiting = waiting.filter((h) => !deleted.includes(h.id)); c.status(204) },
  })
  const got = []
  listen(waka.onHint((h) => got.push(h.key)))
  await openStream()
  assert.deepEqual(got, ['album:1'])
  assert.deepEqual(deleted, ['h1'])

  waiting = [{ id: 'h2', key: 'album:2', from_server: { id: 'srv' }, blob: '' }]
  net.dial.event('hint', 'h2')
  await flush(8)
  assert.deepEqual(got, ['album:1', 'album:2'])

  // Sent while the stream was down: nothing announced it.
  net.dial.cut()
  await flush()
  waiting = [{ id: 'h3', key: 'album:3', from_server: { id: 'srv' }, blob: '' }]
  await advance(1000)
  await openStream('s2')
  await flush(8)
  assert.deepEqual(got, ['album:1', 'album:2', 'album:3'])
  assert.deepEqual(deleted, ['h1', 'h2', 'h3'])
})

test('a hint whose listener throws is kept and comes again', async () => {
  await client()
  const deleted = []
  hub({
    'GET /api/hints': (c) => c.json([{ id: 'h1', key: 'k', from_server: { id: 'srv' }, blob: '' }]),
    'DELETE /api/hints/*': (c) => { deleted.push(1); c.status(204) },
  })
  let broken = true
  let calls = 0
  listen(waka.onHint(async () => { calls++; if (broken) throw new Error('sync failed') }))
  await openStream()
  await flush(8)
  net.dial.event('hint', 'h1')
  await flush(8)
  assert.ok(calls >= 2, 'delivered again')
  assert.deepEqual(deleted, [])
  broken = false
  net.dial.event('hint', 'h1')
  await flush(8)
  assert.deepEqual(deleted, [1])
})

test('hints still arrive after the hub failed to list them once', async () => {
  await client()
  let fail = true
  hub({
    'GET /api/hints': (c) => (fail ? c.fail() : c.json([{ id: 'h1', key: 'k', from_server: { id: 'srv' }, blob: '' }])),
    'DELETE /api/hints/*': (c) => c.status(204),
  })
  const got = []
  listen(waka.onHint((h) => got.push(h.key)))
  await openStream()
  await flush(8)
  fail = false
  net.dial.event('hint', 'h1')
  await flush(8)
  assert.deepEqual(got, ['k'])
})

test('the hub ending the session signs the device out and says so', async () => {
  await client()
  await storage.set('directory', [{ id: 'srv' }])
  let ended = 0
  waka.onSessionEnded(() => ended++)
  listen(waka.subscribe(() => {}))
  await openStream()
  // Signed out from another device: the hub closes the stream, then refuses.
  net.dial.end()
  await advance(1000)
  net.dial.status(401)
  await flush(8)
  assert.equal(ended, 1)
  assert.equal(waka.connectionState, 'disconnected')
  assert.equal(await waka.isLoggedIn(), false)
  assert.equal(await waka.cachedDirectory(), null)
  await advance(120000, 1000)
  assert.equal(net.dials.length, 2)
})

test('a 401 on any call ends the session once, and logout does not report it', async () => {
  await client()
  hub({ 'GET /api/me': (c) => c.json({ error: 'unauthorized' }, 401), 'POST /api/session/logout': (c) => c.status(204) })
  let ended = 0
  waka.onSessionEnded(() => ended++)
  await assert.rejects(Promise.all([waka.me(), waka.me()].map((p) => p.catch((e) => { throw e }))), { status: 401 })
  await flush()
  assert.equal(ended, 1)

  await storage.set('session', { token: 'wkh_two', expiresAt: FAR })
  await waka.logout()
  assert.equal(ended, 1)
})

test('a late 401 for an old session does not undo a new login', async () => {
  await client()
  const old = waka.me()
  old.catch(() => {})
  await flush()
  await storage.set('session', { token: 'wkh_two', expiresAt: FAR })
  net.to('/api/me')[0].json({ error: 'unauthorized' }, 401)
  await assert.rejects(old, { status: 401 })
  assert.equal(await waka.isLoggedIn(), true)
  assert.equal((await storage.get('session')).token, 'wkh_two')
})

test('the stream starts by itself after signing in', async () => {
  await client({ signedIn: false })
  hub({
    'POST /auth/redeem': (c) => c.json({ token: 'wkh_new', expires_at: FAR, user: { handle: 'alice' } }),
    'POST /api/devices': (c) => c.json({ id: 'dev1' }),
  })
  const states = []
  listen(waka.onConnectionState((s) => states.push(s)))
  await flush()
  assert.equal(net.dials.length, 0)
  assert.equal(waka.connectionState, 'disconnected')

  const url = new URL(await waka.beginLogin())
  await waka.completeLogin(`http://app/?code=c1&state=${url.searchParams.get('state')}`)
  await openStream()
  assert.equal(waka.connectionState, 'connected')
  assert.equal(net.dial.init.headers.Authorization, 'Bearer wkh_new')
})

test('a call the hub never answers times out', async () => {
  await client()
  const me = waka.me()
  me.catch(() => {})
  await advance(14000, 500)
  assert.equal(net.to('/api/me')[0].aborted, false)
  await advance(1500, 500)
  await assert.rejects(me, { name: 'WakaError', status: 0, message: 'timed out' })
  assert.equal(net.to('/api/me')[0].aborted, true)
  // Not a refusal: the session stays.
  assert.equal(await waka.isLoggedIn(), true)
})

test('directory falls back to the last list when the hub is down, slow or replaced by a portal', async () => {
  await client()
  const list = [{ id: 'srv', name: 'Home', address: 'http://srv', app: 'notes' }]
  hub({ 'GET /api/directory': (c) => c.json(list) })
  assert.deepEqual(await waka.directory(), list)

  hub({ 'GET /api/directory': (c) => c.fail() })
  assert.deepEqual(await waka.directory(), list)

  hub({ 'GET /api/directory': (c) => c.html(200) })
  assert.deepEqual(await waka.directory(), list)
  assert.deepEqual(await waka.cachedDirectory(), list, 'the portal page did not replace the list')

  hub({ 'GET /api/directory': (c) => c.json({ error: 'boom' }, 503) })
  assert.deepEqual(await waka.directory(), list)

  hub({})
  const slow = waka.directory()
  await advance(15500, 500)
  assert.deepEqual(await slow, list)

  // A refusal is an answer, not an outage.
  hub({ 'GET /api/directory': (c) => c.json({ error: 'nope' }, 403) })
  await assert.rejects(waka.directory(), { status: 403 })
})

test('failures to connect are WakaErrors with status 0', async () => {
  await client()
  hub({ 'GET /api/me': (c) => c.fail() })
  await assert.rejects(waka.me(), (err) => err.name === 'WakaError' && err.status === 0 && err.cause instanceof TypeError)
})

// --- servers ---

const SRV = { id: 'srv', name: 'Home', address: 'http://srv' }

function servers({ hubUp = true } = {}) {
  let sessions = 0
  net.route = (call) => {
    if (call.url === `${HUB}/oauth/token`) {
      if (hubUp === 'refused') return call.fail()
      return hubUp ? call.json({ access_token: 'jwt' }) : null // null: never answers
    }
    if (call.url === 'http://srv/waka/session') {
      const now = Math.floor(Date.now() / 1000)
      return call.json({ session: `sess${++sessions}`, expires_at: now + 7 * 86400, user: { handle: 'alice' } })
    }
    if (call.url === 'http://srv/api/notes') return call.json({ auth: call.init.headers.Authorization })
  }
  return { set hubUp(v) { hubUp = v }, get sessions() { return sessions } }
}

test('a server session outlives the hub', async () => {
  await client()
  const s = servers()
  const conn = waka.server(SRV)
  assert.equal((await conn.request('GET', '/api/notes')).auth, 'Bearer sess1')
  s.hubUp = false
  // A day later the hub is still down. The server does not care.
  await advance(86400_000, 3600_000)
  assert.equal((await conn.request('GET', '/api/notes')).auth, 'Bearer sess1')
  assert.equal(net.to('/oauth/token').length, 1)
})

test('renewal past half-life never delays a call, and is not retried in a loop', async () => {
  await client()
  const s = servers()
  const conn = waka.server(SRV)
  await conn.request('GET', '/api/notes')
  s.hubUp = false
  await advance(4 * 86400_000, 3600_000)

  // The hub hangs. Calls must still go straight through on the old session.
  for (let i = 0; i < 5; i++) assert.equal((await conn.request('GET', '/api/notes')).auth, 'Bearer sess1')
  assert.equal(net.to('/oauth/token').length, 2, 'one renewal attempt, not one per call')

  await advance(61_000, 1000)
  await conn.request('GET', '/api/notes')
  assert.equal(net.to('/oauth/token').length, 3)

  // Same when the hub refuses at once instead of hanging: one try a minute.
  s.hubUp = 'refused'
  await advance(61_000, 1000)
  for (let i = 0; i < 5; i++) { await conn.request('GET', '/api/notes'); await flush() }
  assert.equal(net.to('/oauth/token').length, 4)

  // The hub is back: the next attempt renews, and calls move to the new session.
  s.hubUp = true
  await advance(61_000, 1000)
  await conn.request('GET', '/api/notes')
  await flush(8)
  assert.equal((await conn.request('GET', '/api/notes')).auth, 'Bearer sess2')
})

test('an expired server session with the hub down fails as unreachable, not as a hang', async () => {
  await client()
  const s = servers()
  const conn = waka.server(SRV)
  await conn.request('GET', '/api/notes')
  s.hubUp = false
  await advance(8 * 86400_000, 3600_000)
  const call = conn.request('GET', '/api/notes')
  call.catch(() => {})
  await advance(16000, 500)
  await assert.rejects(call, { status: 0 })
})

test('a 401 from the server renews the session and repeats the call once', async () => {
  await client()
  servers()
  const conn = waka.server(SRV)
  await conn.request('GET', '/api/notes')
  const base = net.route
  let refused = 0
  net.route = (call) => {
    if (call.url === 'http://srv/api/notes' && call.init.headers.Authorization === 'Bearer sess1') { refused++; return call.json({ error: 'expired' }, 401) }
    return base(call)
  }
  assert.equal((await conn.request('GET', '/api/notes')).auth, 'Bearer sess2')
  assert.equal(refused, 1)
})

test('tracks whether a server is reachable', async () => {
  await client()
  servers()
  const conn = waka.server(SRV)
  const seen = []
  conn.onReachable((r) => seen.push(r))
  assert.equal(conn.reachable, null)
  await conn.request('GET', '/api/notes')
  assert.equal(conn.reachable, true)

  const up = net.route
  net.route = (call) => (call.url.startsWith('http://srv') ? call.fail() : up(call))
  await assert.rejects(conn.request('GET', '/api/notes'))
  await assert.rejects(conn.request('GET', '/api/notes'))
  assert.equal(conn.reachable, false)

  // A tunnel answering for a home server that is off.
  net.route = (call) => (call.url.startsWith('http://srv') ? call.html(502) : up(call))
  await assert.rejects(conn.request('GET', '/api/notes'), { status: 502 })
  assert.equal(conn.reachable, false)

  net.route = (call) => (call.url === 'http://srv/.well-known/waka-server' ? call.json({ server_id: 'srv' }) : up(call))
  assert.equal(await conn.check(), true)

  // A refusal means it is there.
  net.route = (call) => (call.url === 'http://srv/api/notes' ? call.json({ error: 'no' }, 403) : up(call))
  await assert.rejects(conn.request('GET', '/api/notes'), { status: 403 })
  assert.equal(conn.reachable, true)
  assert.deepEqual(seen, [true, false, true])
})

test('a call the app aborts itself does not mark the server unreachable', async () => {
  await client()
  servers()
  const conn = waka.server(SRV)
  await conn.request('GET', '/api/notes')
  const up = net.route
  net.route = (call) => (call.url === 'http://srv/api/slow' ? null : up(call))
  const abort = new AbortController()
  const slow = conn.fetch('/api/slow', { signal: abort.signal })
  slow.catch(() => {})
  await flush()
  abort.abort()
  await assert.rejects(slow)
  assert.equal(conn.reachable, true)
})
