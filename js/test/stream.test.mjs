// The hub stream's connection handling, against a fake network and a fake
// clock so every timing rule is checked exactly.  node --test sdk/test
import assert from 'node:assert/strict'
import { afterEach, beforeEach, mock, test } from 'node:test'
import { HubStream } from '../src/stream.js'
import { FakeNet, advance, fakeClock, flush, now, sleep } from './fakes.mjs'

let net, states, events, readies, refused, stream

// random 0.5 is no jitter, so delays are the plain curve.
function make(opts = {}) {
  net = new FakeNet()
  states = []
  events = []
  readies = 0
  refused = []
  stream = new HubStream({
    url: 'http://hub/api/events',
    pingUrl: (id) => `http://hub/api/events/${id}/ping`,
    fetch: net.fetch,
    token: async () => 'wkh_token',
    onState: (s) => states.push(s),
    onEvent: (event, data) => events.push([event, data]),
    onReady: () => readies++,
    onUnauthorized: (t) => refused.push(t),
    random: () => 0.5,
    now,
    ...opts,
  })
  return stream
}

async function connected(opts) {
  make(opts).start()
  await flush()
  net.dial.open().hello()
  await flush()
  assert.equal(stream.state, 'connected')
}

beforeEach(() => fakeClock())
afterEach(() => { stream?.stop(); mock.timers.reset() })

test('is connected at the hub\'s hello, not at the response headers', async () => {
  make().start()
  assert.equal(stream.state, 'connecting')
  await flush()
  assert.equal(net.dial.init.headers.Authorization, 'Bearer wkh_token')
  net.dial.open()
  await flush()
  assert.equal(stream.state, 'connecting')
  net.dial.hello()
  await flush()
  assert.deepEqual(states, ['connecting', 'connected'])
  assert.equal(readies, 1)
})

test('parses events split across chunks, CRLF, comments and multi-line data', async () => {
  await connected()
  const d = net.dial
  d.push('event: in')
  await flush()
  d.push('box\ndata: a1\n')
  await flush()
  assert.deepEqual(events, [])
  d.push('\n: ping\n\nevent: hint\r\ndata: h1\r\n\r\ndata:first\ndata: second\n\n')
  await flush()
  assert.deepEqual(events, [['inbox', 'a1'], ['hint', 'h1'], ['message', 'first\nsecond']])
})

test('ignores events that arrive before the hello', async () => {
  make().start()
  await flush()
  net.dial.open().event('inbox', 'early')
  await flush()
  assert.deepEqual(events, [])
})

test('gives up on a dial that never answers and tries again', async () => {
  make().start()
  await advance(9900)
  assert.equal(stream.state, 'connecting')
  await advance(200)
  assert.equal(stream.state, 'reconnecting')
  assert.equal(net.dials[0].aborted, true)
  await advance(1000)
  assert.equal(net.dials.length, 2)
})

test('gives up on a response that never says hello', async () => {
  make().start()
  await flush()
  net.dial.open()
  await advance(10100)
  assert.equal(stream.state, 'reconnecting')
  assert.equal(net.dials[0].aborted, true)
})

test('backs off 1, 2, 4, 8, 16, 30, 30 seconds', async () => {
  make().start()
  await flush()
  const waits = []
  for (let i = 0; i < 7; i++) {
    const n = net.dials.length
    net.dial.fail()
    await flush()
    let waited = 0
    while (net.dials.length === n) { await advance(500, 500); waited += 500 }
    waits.push(waited)
  }
  assert.deepEqual(waits, [1000, 2000, 4000, 8000, 16000, 30000, 30000])
})

test('jitter stays within 20% and never passes the cap', async () => {
  for (const [random, first, capped] of [[0, 800, 24000], [1, 1200, 30000]]) {
    make({ random: () => random }).start()
    await flush()
    net.dial.fail()
    await advance(first - 100)
    assert.equal(net.dials.length, 1, `random ${random}: too early`)
    await advance(200)
    assert.equal(net.dials.length, 2, `random ${random}: too late`)
    for (let i = 0; i < 6; i++) { net.dial.fail(); await advance(31000, 500) }
    const n = net.dials.length
    net.dial.fail()
    await advance(capped - 500, 500)
    assert.equal(net.dials.length, n)
    await advance(1000, 500)
    assert.equal(net.dials.length, n + 1)
    stream.stop()
  }
})

test('a connection that drops straight away does not reset the backoff', async () => {
  make().start()
  await flush()
  net.dial.fail()
  await advance(1000)
  net.dial.fail()
  await advance(2000)
  assert.equal(net.dials.length, 3)
  net.dial.open().hello()
  await advance(5000)
  net.dial.cut()
  // Third failure in a row: 4 s, not 1 s.
  await advance(3500)
  assert.equal(net.dials.length, 3)
  await advance(1000)
  assert.equal(net.dials.length, 4)
})

test('a minute connected resets the backoff', async () => {
  make().start()
  await flush()
  for (let i = 0; i < 3; i++) { net.dial.fail(); await advance(8000, 500) }
  net.dial.open().hello()
  for (let i = 0; i < 7; i++) { await advance(10000, 500); net.dial.keepalive() }
  assert.equal(stream.state, 'connected')
  const n = net.dials.length
  net.dial.cut()
  await advance(1100)
  assert.equal(net.dials.length, n + 1)
})

test('reconnects when the hub closes the stream', async () => {
  await connected()
  net.dial.end()
  await flush()
  assert.equal(stream.state, 'reconnecting')
  await advance(1000)
  net.dial.open().hello()
  await flush()
  assert.deepEqual(states, ['connecting', 'connected', 'reconnecting', 'connected'])
  assert.equal(readies, 2)
})

test('watchdog: two missed keep-alives is a dead stream', async () => {
  await connected()
  // Keep-alives every 25 s keep it up indefinitely.
  for (let i = 0; i < 8; i++) { await advance(25000, 500); net.dial.keepalive() }
  assert.equal(stream.state, 'connected')
  assert.equal(net.dials.length, 1)
  // Then the network drops it without a word.
  await advance(49000, 500)
  assert.equal(stream.state, 'connected')
  await advance(14000, 500)
  assert.equal(stream.state, 'reconnecting')
  assert.equal(net.dials[0].aborted, true)
})

test('watchdog follows the keep-alive the hub announces', async () => {
  make().start()
  await flush()
  net.dial.open().hello('s1', 2000)
  await advance(3900)
  assert.equal(stream.state, 'connected')
  await advance(1200)
  assert.equal(stream.state, 'reconnecting')
})

test('a hint probes a live stream, and a pong settles it', async () => {
  await connected()
  stream.hint(true)
  await flush()
  assert.equal(net.pings.length, 1)
  assert.equal(net.pings[0].url, 'http://hub/api/events/s1/ping')
  assert.equal(net.pings[0].method, 'POST')
  net.pings[0].status(204)
  net.dial.event('pong', 's1')
  await advance(15000, 500)
  assert.equal(stream.state, 'connected')
  assert.deepEqual(events, [])
})

test('an offline hint probes too', async () => {
  await connected()
  stream.hint(false)
  await flush()
  assert.equal(net.pings.length, 1)
})

test('a probe with no pong is a dead stream after 10 seconds', async () => {
  await connected()
  stream.hint(true)
  await flush()
  net.pings[0].status(204)
  await advance(9500)
  assert.equal(stream.state, 'connected')
  await advance(1000)
  assert.equal(stream.state, 'reconnecting')
})

test('a probe the hub does not recognise reconnects at once', async () => {
  await connected()
  stream.hint(true)
  await flush()
  net.pings[0].status(404)
  await flush()
  assert.equal(stream.state, 'reconnecting')
})

test('a probe that cannot be sent proves nothing about the stream', async () => {
  await connected()
  stream.hint(false)
  await flush()
  net.pings[0].fail()
  await advance(20000, 500)
  assert.equal(stream.state, 'connected')
  // The probe is free again for the next hint.
  stream.hint(true)
  await flush()
  assert.equal(net.pings.length, 2)
})

test('several hints in a row send one probe', async () => {
  await connected()
  for (let i = 0; i < 5; i++) stream.hint(true)
  await flush()
  assert.equal(net.pings.length, 1)
})

test('waking from sleep probes instead of trusting the stream', async () => {
  await connected()
  await advance(5000)
  sleep(10 * 60 * 1000)
  await advance(13000, 500)
  assert.equal(net.pings.length, 1)
  assert.equal(stream.state, 'connected')
  // No pong: the stream died while the device slept.
  await advance(10000, 500)
  assert.equal(stream.state, 'reconnecting')
})

test('a live stream survives sleep when it answers the probe', async () => {
  await connected()
  sleep(10 * 60 * 1000)
  await advance(13000, 500)
  net.pings[0].status(204)
  net.dial.event('pong', 's1')
  await advance(20000, 500)
  net.dial.keepalive()
  await advance(20000, 500)
  assert.equal(stream.state, 'connected')
  assert.equal(net.dials.length, 1)
})

test('an online hint cuts a backoff wait short and restarts the curve', async () => {
  make().start()
  await flush()
  for (let i = 0; i < 5; i++) { net.dial.fail(); await advance(16000, 500) }
  net.dial.fail()
  await flush()
  const n = net.dials.length
  // An offline hint must not dial.
  stream.hint(false)
  await flush()
  assert.equal(net.dials.length, n)
  stream.hint(true)
  await flush()
  assert.equal(net.dials.length, n + 1)
  net.dial.fail()
  await advance(1100)
  assert.equal(net.dials.length, n + 2)
})

test('an online hint abandons a dial that has hung for a while', async () => {
  make().start()
  await advance(3000)
  stream.hint(false)
  await flush()
  assert.equal(net.dials.length, 1)
  stream.hint(true)
  await flush()
  assert.equal(net.dials.length, 2)
  assert.equal(net.dials[0].aborted, true)
  net.dial.open().hello()
  await flush()
  assert.equal(stream.state, 'connected')
})

test('a hint during a dial does not start a second one', async () => {
  make().start()
  await flush()
  stream.hint(true)
  stream.hint(true)
  await flush()
  assert.equal(net.dials.length, 1)
})

test('a refused session ends the stream and is reported once', async () => {
  make().start()
  await flush()
  net.dial.status(401)
  await flush()
  assert.equal(stream.state, 'disconnected')
  assert.deepEqual(refused, ['wkh_token'])
  await advance(120000, 1000)
  assert.equal(net.dials.length, 1)
})

test('does not dial when nobody is signed in', async () => {
  make({ token: async () => { throw new Error('not signed in') } }).start()
  await advance(60000, 1000)
  assert.equal(stream.state, 'disconnected')
  assert.equal(net.calls.length, 0)
  assert.deepEqual(refused, [])
})

test('a captive portal or a failing proxy is not a connection', async () => {
  make().start()
  await flush()
  net.dial.html(200)
  await flush()
  assert.equal(stream.state, 'reconnecting')
  await advance(1000)
  // A page that keeps loading is refused on sight, not after the handshake deadline.
  net.dial.open({ 'content-type': 'text/html' }, 200).push('<html>')
  await flush()
  assert.equal(net.dial.aborted, true)
  await advance(2000)
  net.dial.open({ 'content-type': 'text/html' }, 502).push('<html>Bad gateway</html>')
  await flush()
  assert.equal(stream.state, 'reconnecting')
  // Bytes from a broken answer must not reset the backoff: next is 4 s.
  await advance(3500)
  assert.equal(net.dials.length, 3)
  await advance(600)
  assert.equal(net.dials.length, 4)
  assert.equal(readies, 0)
})

test('an event that never ends is cut off', async () => {
  await connected()
  net.dial.push('data: ' + 'x'.repeat(70000))
  await flush()
  assert.equal(stream.state, 'reconnecting')
})

test('stop aborts the dial and nothing happens afterwards', async () => {
  await connected()
  stream.stop()
  assert.equal(stream.state, 'disconnected')
  assert.equal(net.dials[0].aborted, true)
  await advance(300000, 1000)
  assert.equal(net.calls.length, 1)
  assert.deepEqual(states, ['connecting', 'connected', 'disconnected'])
})

test('stop while waiting to retry cancels the retry', async () => {
  make().start()
  await flush()
  net.dial.fail()
  await flush()
  stream.stop()
  await advance(60000, 1000)
  assert.equal(net.dials.length, 1)
  stream.hint(true)
  await flush()
  assert.equal(net.dials.length, 1)
})

test('an answer to an abandoned dial is ignored', async () => {
  make().start()
  await flush()
  const old = net.dial
  stream.stop()
  stream.start()
  await flush()
  // The old request was aborted, but suppose its answer raced the abort.
  old.resolve(new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('event: hello\ndata: {}\n\n')) } }),
    { headers: { 'content-type': 'text/event-stream' } }))
  await flush()
  assert.equal(stream.state, 'connecting')
  net.dial.open().hello()
  await flush()
  assert.equal(stream.state, 'connected')
  assert.equal(readies, 1)
})

test('start after stop begins again as a first connection', async () => {
  await connected()
  net.dial.cut()
  await flush()
  stream.stop()
  states.length = 0
  stream.start()
  await flush()
  net.dial.open().hello()
  await flush()
  assert.deepEqual(states, ['connecting', 'connected'])
})

test('survives a storm of drops with one live dial at the end', async () => {
  await connected()
  let seed = 7
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648
  for (let i = 0; i < 200; i++) {
    const d = net.dial
    const r = rnd()
    if (stream.state === 'connected') {
      if (r < 0.3) d.cut()
      else if (r < 0.5) d.end()
      else if (r < 0.7) stream.hint(rnd() < 0.5)
      else d.keepalive()
    } else if (d && !d.aborted && !d.controller) {
      if (r < 0.3) d.fail()
      else if (r < 0.4) d.status(503)
      else if (r < 0.5) d.html()
      else d.open().hello('s' + i)
    } else if (r < 0.5) {
      stream.hint(true)
    }
    for (const p of net.pings) if (!p.answered) { p.answered = true; rnd() < 0.5 ? p.status(204) : p.fail() }
    await advance(Math.floor(rnd() * 3000), 250)
  }
  // Let it settle on a healthy hub.
  net.route = (call) => {
    if (call.url.endsWith('/ping')) call.status(204)
    else call.open().hello('final')
  }
  await advance(120000, 1000)
  assert.equal(stream.state, 'connected')
  const live = net.dials.filter((d) => !d.aborted && d.controller && d.controller.desiredSize !== null)
  assert.equal(live.length, 1, 'exactly one stream is open')
  live[0].event('inbox', 'after-the-storm')
  await flush()
  assert.deepEqual(events.at(-1), ['inbox', 'after-the-storm'])
})
