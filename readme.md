# Waka SDK

Libraries for apps that sign in with Waka Hub.

| Folder | Package | Install |
|---|---|---|
| [`go/`](go) | Server library (`package waka`): verifies hub tokens, issues the server's sessions, owns grants, links and permission checks | `go get github.com/azukaar/waka-sdk/go` |
| [`js/`](js) | Client SDK (`@waka/client`): login, per-server sessions, directory, inbox and device keys. Logic only, no UI | `npm install @waka/client` |

Docs: [server library](docs/server-library.md), [client SDK](docs/client-sdk.md).

## Releasing

Both packages share one version, the one in `js/package.json`. Bump it and push to `main`: CI tags `go/v<version>` for Go and publishes `@waka/client` to npm (`scripts/release.sh`).
