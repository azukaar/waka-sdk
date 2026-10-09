# Client SDK

`js/` is the JavaScript package (`@waka/client`) every app front end uses to talk to the hub and to app servers. It is logic only; the UI components are in beyond-framework. Types are in `js/src/index.d.ts`.

```
npm install @waka/client
```

## Setup

```js
import { WakaClient } from '@waka/client'

const waka = new WakaClient({
  hubUrl: 'https://hub.example',
  redirectUri: 'https://app.example/',   // registered on the hub for this app
})
```

| Option | Default | |
|---|---|---|
| `hubUrl` | required | |
| `redirectUri` | | Where the hub sends the browser back after login. It must be registered on the hub as a redirect URI of the app's client, which is how the hub knows the app. A native app listening on a loopback port registers `http://127.0.0.1/path` and may use any port |
| `storage` | `BrowserStorage` (IndexedDB) | Any object with async `get`, `set`, `delete`. `MemoryStorage` for tests |
| `fetch` | global `fetch` | |
| `deviceName` | user agent | Shown in the user's device list |
| `requestTimeoutMs` | 15000 | Deadline for each hub and sign-in call |
| `connection` | | Timing of the hub stream: `backoff`, `handshakeTimeoutMs`, `probeTimeoutMs`. See Connection |

Storage holds the hub session, the device's sealing keys (one per server), the last directory and one session per server. The private keys are not extractable.

Failed calls throw `WakaError` with a `status`. Status 0 means there was no usable answer: the hub or server could not be reached, the call timed out, or something else replied (a Wi-Fi sign-in page, for instance). A status 0 never signs the device out.

## Login

One prompt per device.

```js
if (!(await waka.handleRedirect()) && !(await waka.isLoggedIn())) {
  await waka.loginRedirect()
}
```

| Method | |
|---|---|
| `loginRedirect({ prompt?, loginHint? })` | Browser: go to the hub to sign in |
| `handleRedirect()` | Browser: finish a login if the page was opened by the hub's redirect. Returns the user or null |
| `beginLogin(options)` | Returns the URL to open. For apps that drive their own browser window |
| `completeLogin(callbackUrl)` | Finishes a login from the URL the hub redirected to. A code works once |
| `isLoggedIn()` | |
| `logout()` | Signs the device out and forgets every server session |

Completing a login registers this device with the hub. Its sealing key for a server is made on the first token exchange to that server and registered with it, so each server sees a different key for the device, under a different ID.

The session belongs to one app. Everything below (profile, directory, servers, inbox, hints, blocks, lookups) is that app's only.

## Profile

An account has one profile per app, and may override any of it for one server. A server sees the override where there is one, otherwise the app profile.

| Method | |
|---|---|
| `me()` | The app profile: `{ app, handle, name, bio, email, picture }`. The email is only ever shown to the account itself |
| `updateProfile({ handle?, name?, bio? })` | Then renews every open server session, so servers pick the change up at once. Throws with status 409 if the handle is taken |
| `setAvatar(blob)`, `removeAvatar()` | PNG, JPEG, GIF or WebP, up to 512 KB |
| `serverProfile(serverId)` | `{ server_id, override, profile }`: what is overridden for that server (each field null where the app profile applies), and what the server sees |
| `updateServerProfile(serverId, { handle?, name?, bio? })` | A field left out is unchanged; `null` goes back to the app profile. Renews that server's session |
| `clearServerProfile(serverId)` | Drops every override for that server |
| `setServerAvatar(serverId, blob)`, `removeServerAvatar(serverId)` | |
| `lookupUser(handle, { server? })` | Exact handle in this app. Returns `{ handle, name, picture }`, with no ID. Throws with status 404 if there is none |
| `devices()`, `removeDevice(id)` | This app's devices |

Handles are unique within an app, override handles included.

`lookupUser` has no server context unless given one. Without `server`, only app handles match and the answer is the app profile. With `server` (an ID or a directory entry), the handle is resolved as that server sees it, which is how the server itself resolves a share: someone with an override handle there is found only by it. Use that form in a share dialog.

## Directory

| Method | |
|---|---|
| `directory()` | `[{ id, name, address, app, default }]`: this app's servers, its master first. Falls back to the last answer when the hub is unreachable |
| `cachedDirectory()` | The last answer, without asking the hub. Null if there is none. Use it to draw the list at once, then call `directory()` |
| `addServer(address)` | Adds a server by address. This is the consent step for that server |
| `removeServer(id)` | A master server (`default: true`) cannot be removed |
| `registerServer({ name, address })` | For a server you run, in this app. You own it: the server library makes you its admin. Returns its `id` and, once, its `secret` |
| `myServers()`, `deleteServer(id)` | |

## Servers

```js
const photos = waka.server(server)     // an entry from directory(), or an inbox item's from_server
const albums = await photos.joined()   // signs in silently on first use
const res = await photos.fetch('/api/albums/12')
```

A `ServerConnection` gets its session from the hub session with no browser, stores it, and renews it past half its life or on a 401. Renewal past half-life happens behind the call, so a hub that is down or slow never delays a request to a server.

| Method | |
|---|---|
| `fetch(path, init?)` | `fetch` against the server with its session attached. For the app's own routes |
| `request(method, path, body?)` | JSON helper over `fetch`. Throws `WakaError` on failure |
| `user()` | The user as this server knows them |
| `session()` | The current session here as a string, renewed first if it ran out. For a socket that carries it in a message; the server checks it with `SessionPrincipal` |
| `me()` | `{ user, admin, owner }`. `owner`: this account registered the server |
| `renew()` | Force a fresh session |
| `joined()` | What the user owns or has accepted here |
| `joinable()` | What they could join |
| `invites()` | Pending shares on this server |
| `join(resource)`, `leave(grantId)` | |
| `acceptGrant(grantId)`, `declineGrant(grantId)` | |
| `roles(resource)` | The resource's roles, which ones this account may hand out, what it holds, whether it may share and manage. See below |
| `grants(resource)` | Who has access, and links: every link with the manage permission, only one's own without. Each says whether it is `editable` |
| `share(resource, handle, roles)` | By the handle the person has on this server. `roles` is a name or an array. `{ grant, delivered }` |
| `setRoles(grantId, roles)`, `revoke(grantId)` | |
| `createLink(resource, roles, { public?, password?, expiresAt?, maxUses?, label? })` | `{ url, grant }`. For accounts unless `public: true`. The URL is only available here |
| `claimLink(url, password?)` | Turn a link into the user's own grant, with a session here |
| `joinLink(url, { password? })` | The same with the hub login instead, for a server that has not let this account in. Stores the session. Use `waka.joinLink`, which adds the server to the directory first |
| `bans()`, `ban({ userId?, handle?, reason? })`, `unban(userId)` | Server admins |
| `reachable` | Whether the last call got through: `true`, `false`, or `null` before any call. A 502, 503 or 504 counts as not reachable (a tunnel answering for a server that is off) |
| `onReachable(fn)` | Calls back when `reachable` changes. Returns a stop function |
| `check()` | Asks the server whether it is there, with no session needed. Returns `reachable` |

A `resource` is `{ type, id }`.

### Roles

The app server declares which roles a resource has and what each allows; a grant holds a set of them. `roles(resource)` returns everything a share dialog needs:

```js
{
  resource: { type, id },
  roles: [{ name, label, perms, owner, assignable, link, public_link }],
  mine: { roles, perms },      // held on the resource itself; permissions from every source
  can_share, can_manage,
}
```

Offer `assignable` roles for sharing and role changes, `link` ones on a link for accounts, `public_link` ones on a public link. The owner role is never assignable. The server checks all of it again.

## Inbox

```js
const items = await waka.inbox({ status: 'pending' })
const stop = waka.subscribe(() => reload())   // fires when something lands, and on every (re)connect
```

Each item: `{ id, kind, status, created_at, ref, from_server, from_user, body }`. `kind` is `invite` or `notification`. `from_user` is `{ handle, name, picture }`: the sender as they appear on the sending server, with no ID. `body` is the decrypted content, or null when the item was sent before this device signed in.

| Method | |
|---|---|
| `inbox({ status? })` | |
| `subscribe(onItem)` | Calls back with the item ID, and with `null` each time the hub stream is established: anything may have arrived while it was away, so list the inbox again. Returns a stop function |
| `acceptInvite(item)` | Accepts the grant on the sending server, then on the hub, which adds the server to the directory |
| `declineInvite(item)` | Hub only. The sending server is not contacted |
| `inviteDetails(item)` | Reads an invite's details from the sending server, for when `body` is null |
| `markRead(item)`, `deleteInboxItem(item)` | |
| `blockSender(item)` | Blocks whoever sent the item, in this app. Their invites stop arriving |
| `blocks()`, `unblock(blockId)` | Each block shows the person as they appeared where they were blocked |

An invite's `body` from the server library is `{ type: "invite", server, resource: { type, id, title }, roles: [{ name, label }], from: { handle, name }, grant_id }`. A notification's `body` is whatever the app server passed to `Notify`.

`body` is null for an item from a server this device had not signed in to when it was sent: there was no key to seal it to. That is the case for the first invite from a server the person has never used; `inviteDetails` reads it from the server, and signing in there makes the key for what comes next.

## Hints

```js
const stop = waka.onHint(async (hint) => {
  // hint: { id, server, key, body }
  if (hint.key.startsWith('album:')) await myApp.syncAlbum(hint.server, hint.body)
})
```

A hint is a server saying "something changed here". The SDK only calls the listener; whether to sync, how, and whether to open a socket is the app's decision.

- Hints that were waiting are delivered first, then new ones as they arrive. Hints sent while the stream was down are delivered when it comes back.
- A hint is dropped once every listener has returned or its promise resolved. If one throws, the hint stays and comes again.
- Several changes with the same `key` arrive as one hint.
- Hints are best effort and can arrive twice. An app must still sync when it opens.

## Connection

The SDK keeps one stream to the hub, open while anything is listening (`subscribe`, `onHint` or `onConnectionState`) and someone is signed in.

```js
waka.connectionState                       // 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
const stop = waka.onConnectionState((state) => showBanner(state === 'reconnecting'))
waka.onSessionEnded(() => showSignIn())
```

| State | |
|---|---|
| `connecting` | The first attempt |
| `connected` | The hub's hello arrived |
| `reconnecting` | The stream was lost or could not be opened, and is being retried |
| `disconnected` | Nothing is listening, or nobody is signed in |

| Method | |
|---|---|
| `connectionState` | The current state |
| `onConnectionState(fn)` | Calls back on every change. Returns a stop function |
| `checkConnection(online?)` | The network may have changed: check a live stream now, retry now. Pass `false` if the network seems gone |
| `onSessionEnded(fn)` | The hub ended this device's session (signed out from another device, account gone). The SDK has already forgotten the session. Not called by `logout()` |

How the stream is kept alive:

- **Handshake deadline.** A dial that has not reached the hub's hello in 10 seconds is abandoned and retried.
- **Watchdog.** The hub speaks at least every 25 seconds. Two silent intervals mean the network dropped the stream without saying so, and it is redialled.
- **Retries.** 1 second, doubling to 30, each varied by 20%. The delays start over once a connection has lasted a minute.
- **Hints from the platform.** `online`, `offline` and the page becoming visible are never trusted as fact. They only bring a check forward: a connected stream is asked to prove itself within 10 seconds, a wait between retries is skipped, and a dial older than 2 seconds is restarted.
- **Sleep.** A timer that fires much later than it should means the device slept. The stream is checked at once.
- **Catching up.** Events are not replayed. On every connect the SDK delivers waiting hints and calls `subscribe` listeners with `null`.
- **Refusal.** A 401 ends the session: the stream stops, `onSessionEnded` fires once, and nothing is retried until the next login, which restarts the stream by itself.

In a native shell (Tauri on a phone), the webview's own events cover most cases. Call `waka.checkConnection()` from the shell's resume and network-change events as well; it is cheap and does nothing when the stream is fine.

All timings can be set for tests through the `connection` option:

```js
new WakaClient({ hubUrl, connection: { handshakeTimeoutMs: 2000, probeTimeoutMs: 1500, backoff: { baseMs: 200, capMs: 2000 } } })
```

## Links

A link is public (anyone holding it gets in without an account) or for accounts (only a Waka account can join through it). Opening a link should never join by itself: show its card, then let the person choose.

```js
import { openLink, parseLink, previewLink } from '@waka/client'

const card = await previewLink(url, { password })   // or waka.previewLink(url, { password })
// { server: { id, name, address, app }, resource: { type, id, title }, roles: [{ name, label }],
//   invited_by: { handle, name, picture }, public, has_password, locked, expires_at }

const { server, grant } = await waka.joinLink(url, { password })   // join with this account
const link = await openLink(url, { password })                     // public only: { resource, roles, title, fetch }
const res = await link.fetch(`/api/albums/${link.resource.id}`)
```

- `previewLink` needs no session. `invited_by` is whoever made the link, as they appear on that server. `locked`: the link has a password that was not given, so `title` is empty and `invited_by` null until it is.
- `waka.joinLink` is the consent step for that server: it adds it to the directory, exchanges a token for it, and claims the link with that token, which signs in too. It works on a server that only lets in people with a grant. If it fails, a server that was not in the directory before is removed again.
- `openLink` gives an anonymous session limited to a public link, with or without an account. A link for accounts throws 403.
- All three throw 401 when a password is needed or wrong, 404 when the link is dead, and 429 after 10 wrong tries in a minute.

`parseLink(url)` returns `{ address, id, secret }`.

## When the hub is down

- `connectionState` is `reconnecting`.
- `directory()` returns the last list, kept up to date by `addServer`, `removeServer`, `acceptInvite` and `joinLink`.
- Server connections keep working until their session ends (7 days by default), since servers verify sessions themselves.
- Nothing arrives through `subscribe` or `onHint`, and new servers cannot be added. What was missed is delivered when the stream returns.
- Other hub calls fail with status 0 after at most `requestTimeoutMs`. The login is kept.

## Tests

| Command (in `sdk/`) | |
|---|---|
| `npm test` | The connection rules against a fake network and a fake clock: handshake, watchdog, probes, sleep, backoff, refusal, timeouts, reachability. No stack needed |
| `npm run test:chaos` | Builds and starts its own dev stack, then breaks the network between the SDK and it: resets, refused connections, swallowed packets, latency, a killed and restarted stack, a session ended elsewhere. Needs Go |
| `npm run test:e2e` | The ordinary flow against a running dev stack |
