// Registers an app server on a hub and prints its ID and secret.
//
//   node js/tools/register-server.mjs --hub https://hub.example --name "My notes" --address http://localhost:9101
//
// Registering needs a signed-in account, so it opens a login in your browser.
// The hub sends the browser back to http://localhost:9200/, a redirect URI
// of the notes client on the hub; this script listens there to finish the
// login. The server is registered for that client's app, and you own it.
import { createServer } from 'node:http'
import { exec } from 'node:child_process'
import { MemoryStorage, WakaClient } from '../src/index.js'

const args = Object.fromEntries(process.argv.slice(2).map((a, i, all) => (a.startsWith('--') ? [a.slice(2), all[i + 1]] : [])).filter((p) => p.length))
if (!args.hub || !args.name || !args.address) {
  console.error('usage: register-server.mjs --hub <hub url> --name <name> --address <server url> [--port 9200]')
  process.exit(2)
}
const port = Number(args.port || 9200)
const redirectUri = `http://localhost:${port}/`

const waka = new WakaClient({ hubUrl: args.hub, redirectUri, storage: new MemoryStorage(), deviceName: 'register-server' })
const url = await waka.beginLogin()

const callback = new Promise((resolve) => {
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', 'text/plain')
    res.end('Signed in. You can close this tab.')
    server.close()
    resolve(`${redirectUri}${req.url.replace(/^\//, '')}`)
  })
  server.listen(port, '127.0.0.1')
})

console.log(`Sign in here:\n\n  ${url}\n`)
exec(`${process.platform === 'win32' ? 'start ""' : process.platform === 'darwin' ? 'open' : 'xdg-open'} "${url}"`)

const user = await waka.completeLogin(await callback)
console.log(`Signed in as @${user.handle}.`)
const server = await waka.registerServer({ name: args.name, address: args.address })
console.log(`\nRegistered "${server.name}" (${server.address}) on ${args.hub}. The secret is shown only now.\n`)
console.log(`  id:     ${server.id}\n  secret: ${server.secret}\n`)
await waka.logout()
