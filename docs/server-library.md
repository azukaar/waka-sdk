# Server library

`github.com/azukaar/waka-sdk/go` is the Go package (`package waka`) every app server embeds. It verifies hub tokens, issues the server's own sessions, and owns grants, links and the permission check.

```
go get github.com/azukaar/waka-sdk/go
```

```go
import waka "github.com/azukaar/waka-sdk/go"
```

## Setup

```go
w, err := waka.New(ctx, waka.Config{
    Issuer:       "https://hub.example",
    ServerID:     "...",          // from registering the server on the hub
    ServerSecret: "...",
    Name:         "Home photos",
    App:          "photos",
    PublicURL:    "https://photos.example",
    DB:           db,             // *sql.DB; tables are created with a waka_ prefix
    Dialect:      waka.SQLite,    // or waka.Postgres
})

mux.Handle("/waka/", w.Handler())
mux.Handle("/.well-known/waka-server", w.Handler())
http.ListenAndServe(addr, waka.CORS(mux))

w.Register(ctx) // report name and address to the hub; call at startup
```

The `waka_` tables of an older schema are dropped at start-up, not migrated.

### Config

| Field | Default | |
|---|---|---|
| `Issuer` | required | The hub this server belongs to |
| `TrustedIssuers` | `[Issuer]` | Hubs whose tokens are accepted |
| `ServerID`, `ServerSecret` | required | From `POST /api/servers` on the hub |
| `Name`, `App` | | Shown in clients |
| `PublicURL` | | Where clients reach this server |
| `Address` | `PublicURL` | Returns the address to register on the hub. Cosmos supplies its own |
| `Shares` | local links | A `ShareOpener`. Cosmos plugs in here |
| `LinkPath` | `/s/` | Where the app serves its link landing page |
| `DB`, `Dialect` | required, SQLite | |
| `SessionTTL` | 7 days | Fixed life of a server session |
| `Roles` | `DefaultRoles` | `func(ctx, Resource) ([]RoleDef, error)`: the roles a resource offers. See Roles |
| `SharePerm` | `share` | The permission that allows sharing by handle and creating links |
| `ManagePerm` | `manage` | The permission that allows changing and revoking other people's grants and links |
| `AllowLink` | any | `func(ctx, Resource, public bool, roles []string) bool`: which roles a public link, or a link for accounts, may carry |
| `AdminPower` | off | The owner and `Admins` hold every permission on every resource |
| `Admins` | | Handles, on `Issuer` and as seen on this server, of admins besides the owner. The recovery override |
| `SignIn` | `SignInOpen` | `SignInOpen`: any account of the app. `SignInInvite`: only people with a grant (pending included), the owner and `Admins`. Joining through a link is always possible. `SetSignIn` changes it while the server runs |
| `AllowUser` | | An extra check on every sign-in, link joins included |
| `Parent` | | The resource another inherits access from |
| `Describe` | | A resource's display title |
| `Joinable` | | What a user could join but has not |
| `CanJoin` | | The roles a user gets by joining an open resource |
| `AllowGrant` | allowed | `func(ctx, *User, Resource) bool`: asked before a user gains access by a share, a link (claimed or joined), an open join or accepting a pending share. `false` refuses with `ErrForbidden`. The app's own `Grant` and `SetRoles` are not asked. Together keeps someone banned from one realm out of it with this |
| `OnGrant` | | Called after every grant change. See Grant changes |

## Who is asking

```go
p := w.Principal(r)   // *Principal: a user, a link holder, or nil
u := w.User(r)        // *User or nil

mux.HandleFunc("POST /api/albums", w.RequireUser(func(rw http.ResponseWriter, r *http.Request, u *waka.User) { ... }))
```

A session arrives as `Authorization: Bearer <session>` or the `waka_session` cookie. Bans, ended sessions and dead links are re-checked on every call.

For a protocol that carries the session in a message rather than a header (a socket's identify, Hocuspocus `onAuthenticate`):

```go
p, err := w.SessionPrincipal(ctx, raw)   // ErrNoSession, ErrBanned or ErrLinkDead
```

It applies the same checks. The client gets the string from `conn.session()`.

`User.ID` is local to this server and is what an app keys its own data on. The identity is `(User.Issuer, User.Subject)`.

The hub gives every server its own subject for a person, so `Subject` means nothing on another server, and two servers cannot tell they see the same person. The profile (`Handle`, `Name`, `Bio`, avatar) is the one the person shows this server: a per-server override, or their profile in this app. Never pass a user's subject, or any handle other than the one visible here, to other users.

## Owner and admins

The account that registered this server on the hub owns it. The hub says so in the login token, and the library records it at every login.

```go
w.IsOwner(u)   // registered this server
w.IsAdmin(u)   // the owner, or a handle in Config.Admins
```

No admin list or bootstrap invite is needed. `Admins` is the recovery override, matched against the handle visible on this server. With `AdminPower`, admins hold every permission on every resource without a grant.

## Roles and permissions

The app owns the roles; the library keeps the books. A grant records a set of role names, and nothing else about them: which roles exist and what they allow is asked of `Config.Roles` every time, per resource, so roles can change at runtime.

```go
type RoleDef struct {
    Name  string   // stored in grants: keep it stable (an ID, if people rename roles)
    Label string
    Perms []string // the app's own permission strings
    Owner bool     // at most one per resource
}
```

The owner role is never handed out by share, link or role change, and its holder cannot be changed or removed through them, nor leave. Only `Grant` and `SetRoles` give or take it.

Without `Config.Roles`, every resource has `DefaultRoles`:

| Role | Label | Permissions |
|---|---|---|
| `read` | Can view | `read` |
| `edit` | Can edit | `read`, `edit` |
| `admin` | Can share | `read`, `edit`, `share`, `manage` |
| `owner` (owner role) | Owner | `read`, `edit`, `share`, `manage`, `delete` |

A principal's permissions are the union over the roles it holds on the resource, the roles held on each `Parent` up the chain (each resolved against that resource's roles), and everything with `AdminPower`. A link holder has the link's roles. Unknown role names count for nothing.

```go
res := waka.Resource{Type: "album", ID: id}

w.Grant(ctx, res, u.ID, []string{"owner"}, u.ID)   // on creation
if !w.Has(ctx, p, res, "edit") { ... }               // the permission check
w.DeleteResource(ctx, res)                           // when the resource is deleted
```

| Function | |
|---|---|
| `Has(ctx, p, res, perm) bool` | Whether the principal holds the permission. A failing `Roles` hook counts as no |
| `Perms(ctx, p, res) []string` | Every permission it holds there |
| `RolesOf(ctx, p, res) []string` | The roles it holds on the resource itself |
| `RolesFor(ctx, res) ([]RoleDef, error)` | The resource's roles |
| `RoleInfo(ctx, u, res) (*RoleInfo, error)` | What `GET /waka/roles` answers |
| `Joined(ctx, userID)` | Accepted grants: what the user owns and has accepted |
| `Invites(ctx, userID)` | Pending grants |
| `GrantsOn(ctx, res)` | Every grant and live link on a resource |
| `HasAnyGrant(ctx, userID)` | Anything shared with the user and not declined |
| `GrantOf(ctx, res, userID)` | The user's one grant on the resource, in any status, or `ErrNoSuchGrant` |

### What the app does directly

Nothing is checked; the app decides.

| Function | |
|---|---|
| `Grant(ctx, res, userID, roles, by) (*Grant, error)` | Adds roles to the user's grant, accepted, creating it if needed |
| `SetRoles(ctx, g, roles, by) (*Grant, error)` | Replaces a grant's roles, owner role included: an ownership transfer, the app's own role editor |
| `Revoke(ctx, g) error` | Removes a user grant or kills a link |
| `DeleteResource(ctx, res) error` | Removes every grant on a resource |

### On someone's behalf

These check the rules below; the HTTP routes use them.

| Function | |
|---|---|
| `Share(ctx, by, res, handle, roles) (*Grant, bool, error)` | See Sharing |
| `ShareUser(ctx, by, res, userID, roles) (*Grant, bool, error)` | The same for someone this server already knows, by local ID. The hub only delivers the invite |
| `CreateLink(ctx, by, ShareSpec) (*Link, error)` | See Links |
| `ChangeRoles(ctx, by, grantID, roles) (*Grant, error)` | Replaces the roles of someone else's grant or of a link |
| `RemoveGrant(ctx, by, grantID) error` | Revokes someone else's grant or a link |
| `CanChange(ctx, by, g) bool` | Whether `by` may change or revoke `g` |
| `Accept`, `Decline(ctx, u, grantID)`, `Leave(ctx, u, grantID)` | The user's own grant. The owner cannot leave |
| `Join(ctx, u, res) (*Grant, error)` | An open resource, with the roles `CanJoin` gives |

The rules:

- Handing out roles (share, link, role change) needs `SharePerm`, and every permission of every role handed out. Never the owner role.
- Changing or revoking a grant needs `SharePerm` for one's own links and pending invites, and `ManagePerm` for anything else. The grant's holder must hold no permission the caller lacks (for a link, its roles; for a person, everything they hold there). Nobody changes their own grant this way; they leave.
- Sharing with someone who already has access adds roles to their grant, under the same rule.

Together's realm: `SharePerm: "CREATE_INVITE"`, `ManagePerm: "MANAGE_INVITES"`, and `Roles` returning the realm's roles with their permission bits as strings.

## Grant changes

`Config.OnGrant(ctx, GrantChange) error` is called after each change has been written, synchronously, in the request that made it. An error is logged; the change stands.

```go
type GrantChange struct {
    Type          ChangeType
    Resource      Resource
    Before, After *Grant // Before nil for a new grant, After nil for a removed one
    By            *User  // who acted; nil when the app called without naming anyone
}
```

| `Type` | |
|---|---|
| `created` | A share by handle (pending) or a new link |
| `granted` | The app's `Grant` |
| `accepted`, `declined` | An answer to a pending share |
| `joined` | An open resource joined through `CanJoin` |
| `claimed` | A link turned into the user's grant (claim or join) |
| `left` | The user gave up their grant |
| `revoked` | A grant removed, or a link killed, by someone else or the app |
| `roles_changed` | `ChangeRoles`, `SetRoles`, or a share adding roles to an existing grant |
| `resource_deleted` | `DeleteResource`. Before and After are nil |

## Sharing

```go
grant, delivered, err := w.Share(ctx, by, res, "bob", []string{"edit"})
```

Looks the handle up on the hub as this server sees it, creates a pending grant, and posts an encrypted invite to the recipient's hub inbox. The handle is the one the person has here: someone with an override handle on this server is found only by it. `delivered` is false when the grant was made but the hub did not take the invite; the recipient still finds it when they sign in here.

## Links

A link is either public or for accounts:

- **Public**: anyone holding it gets its roles without an account, signed in or not (`RedeemLink`).
- **For accounts** (the default): no anonymous session. A Waka account claims it as a grant of its own.

Any link can be claimed. Opening one never joins by itself: the client shows a preview and the person chooses to join.

```go
link, err := w.CreateLink(ctx, by, waka.ShareSpec{Resource: res, Roles: []string{"read"}, Public: false,
    Password: "...", ExpiresAt: 0, MaxUses: 0, Label: ""})
// link.URL is only available now

preview, err := w.PreviewLink(ctx, linkID, secret, password)       // the card, no session needed
session, grant, err := w.RedeemLink(ctx, linkID, secret, password)  // public only: anonymous session limited to the link
grant, err := w.ClaimLink(ctx, user, linkID, secret, password)      // the signed-in user's own grant
session, grant, err := w.JoinLink(ctx, hubToken, linkID, secret, password) // the same with a hub token, signing them in
```

`AllowLink` decides which roles each kind may carry on a resource (Together: public links only with read-only roles). `JoinLink` skips `SignIn`, so a link works on an invite-only server. Claiming adds the link's roles to any the user holds; `MaxUses` counts claims that changed something.

A link with a password shows its title and who made it only with the right password. Wrong passwords, and wrong secrets for a link ID, count as tries: 10 a minute per link, then 429.

## Reaching users through the hub

```go
w.Notify(ctx, userID, payload)            // shown to the person
w.Hint(ctx, userID, "album:12", payload)  // for their client only: something changed, come and sync
```

Both encrypt `payload` (any JSON value) to each of the user's devices, with the key each device made for this server. The user must have this server in their directory. A device that never signed in here has no key, and gets nothing.

A hint is a poke, not the change. A newer hint with the same key replaces a waiting one, and delivery is best effort, so clients must be able to catch up from the server on their own. The key is visible to the hub; keep content out of it.

`LookupUser(ctx, handle)` finds an account of this server's app by the exact handle visible here. `HubUser.ID` is this server's subject for them. There is no lookup by email.

Every call to the hub names users by this server's subjects, and gets them back the same way.

## Bans and sessions

```go
w.Ban(ctx, user, "reason")   // stops the identity and ends its sessions
w.Unban(ctx, user)           // it may sign in again at once
w.EndSessions(ctx, user)     // ends its sessions; it may sign in again
```

Admins can ban; an admin cannot be banned.

## Errors

`ErrForbidden`, `ErrBanned`, `ErrNotAllowed`, `ErrNoSession`, `ErrUserNotFound`, `ErrNoSuchGrant`, `ErrNotApplicable`, `ErrBadRole`, `ErrLinkDead`, `ErrAccountsOnly`, `ErrBadPassword`, `ErrTooManyTries`, and `*HubError` for a refusal from the hub.

## HTTP routes served by `Handler()`

JSON in and out. Errors are `{"error": "message"}`. Routes marked User need a signed-in user.

### Sessions

| Route | | |
|---|---|---|
| `GET /.well-known/waka-server` | | `{ "server_id", "issuer", "name", "app", "sign_in" }`. `sign_in` is `open` or `invite` |
| `POST /waka/session` | `{"token": "<per-server hub token>"}` | `{ "session", "expires_at", "user" }`. 401 for a bad token, 403 if banned or not allowed |
| `GET /waka/login?return=/path` | | For a web page served by this server: redirects to the hub and back, then sets the `waka_session` cookie |
| `GET /waka/callback` | | The hub's redirect target for the above |
| `POST /waka/logout` | | Clears the cookie. 204 |
| `GET /waka/me` | User | `{ "user", "admin", "owner" }` |
| `GET /waka/users/{id}/avatar` | | This server's copy of a user's avatar |

`user` is `{ "id", "issuer", "subject", "handle", "name", "bio", "avatar" }`; `avatar` is a path on this server or `""`.

### Membership

| Route | | |
|---|---|---|
| `GET /waka/joined` | User | Accepted grants, each with `title` |
| `GET /waka/invites` | User | Pending grants, each with `title` and `invited_by` |
| `GET /waka/joinable` | User | `[{ "resource", "title", "roles", "info"? }]` from `Config.Joinable`. `info` is whatever the app adds |
| `POST /waka/join` | User, `{"type", "id"}` | Joins an open resource if `Config.CanJoin` allows. Returns the grant |
| `POST /waka/grants/{id}/accept` | User | Accepts a pending grant. 204 |
| `POST /waka/grants/{id}/decline` | User | 204 |
| `POST /waka/grants/{id}/leave` | User | Gives up an accepted grant. Not for the owner role. 204 |

### Managing access

| Route | | |
|---|---|---|
| `GET /waka/roles?type=&id=` | User | The resource's roles and what the caller may do with them. 403 for someone holding nothing there |
| `GET /waka/grants?type=&id=` | User, `SharePerm` | Every user grant and the caller's own links; every link with `ManagePerm`. Each with `user`, `invited_by` and `editable` |
| `POST /waka/grants` | User, `{"resource", "target", "roles"}` | Shares with a handle, as seen on this server. `{ "grant", "delivered" }` |
| `PATCH /waka/grants/{id}` | User, `{"roles"}` | Replaces the roles of a grant or link |
| `DELETE /waka/grants/{id}` | User | Removes a grant or revokes a link. 204 |
| `POST /waka/links` | User, `{"resource", "roles", "public"?, "password"?, "expires_at"?, "max_uses"?, "label"?}` | `{ "grant", "url" }`. The URL is returned only here |

`GET /waka/roles` answers:

```json
{ "resource": { "type", "id" },
  "roles": [{ "name", "label", "perms", "owner", "assignable", "link", "public_link" }],
  "mine": { "roles", "perms" },
  "can_share", "can_manage" }
```

`assignable`: the caller may hand the role out by sharing or a role change. `link` and `public_link`: it may also go on a link for accounts, or a public one, as `AllowLink` decides. `mine.roles` are held on the resource itself; `mine.perms` come from every source.

A grant is:

```json
{ "id", "resource": { "type", "id" }, "kind": "user", "user_id", "roles": ["edit"], "status": "pending", "created_by", "created_at",
  "link_id", "public", "label", "expires_at", "revoked_at", "max_uses", "uses", "has_password" }
```

The last line applies to `kind: "link"`.

### Links

A link URL is `<PublicURL><LinkPath><link id>#<secret>`. The secret is in the fragment and never sent in a request line. Each route takes `{"id", "secret", "password"?}`.

| Route | | |
|---|---|---|
| `POST /waka/links/preview` | | The card below. No session |
| `POST /waka/links/redeem` | | Public links: `{ "session", "expires_at", "resource", "roles", "title" }`. 403 for a link for accounts |
| `POST /waka/links/claim` | User | Returns the user's grant |
| `POST /waka/links/join` | `"token"`: a per-server hub token | `{ "session", "expires_at", "user", "grant" }`. Claims and signs in, even where `SignIn` would refuse. 401 for a bad token |

All four answer 401 `password required` or `wrong password`, 404 for a dead link, and 429 after 10 wrong tries in a minute.

The card:

```json
{ "server": { "id", "name", "address", "app" },
  "resource": { "type", "id", "title" },
  "roles": [{ "name", "label" }],
  "invited_by": { "handle", "name", "picture" },
  "public", "has_password", "locked", "expires_at" }
```

`invited_by` is whoever made the link, as they appear on this server; `picture` is an absolute URL or `""`. `locked`: the link has a password that was not given, so `title` is empty and `invited_by` null.

### Bans

Server admins only.

| Route | | |
|---|---|---|
| `GET /waka/bans` | User | `[{ "user_id", "handle", "name", "issuer", "reason", "created_at" }]` |
| `POST /waka/bans` | User, `{"user_id" or "handle", "reason"?}` | Bans by local ID, or by handle for someone not seen yet |
| `DELETE /waka/bans/{id}` | User | By local user ID. 204 |

## Where Cosmos plugs in

```go
type ShareOpener interface {
    Open(ctx context.Context, spec ShareSpec) (externalID, url string, err error)
    Close(ctx context.Context, externalID string) error
    Verify(r *http.Request) (externalID string, ok bool)
}
```

With a `ShareOpener` set, a link's secret, password, expiry and hostname belong to it, and this server keeps only the share ID, the resource and the roles. `Verify` is how a forwarded request is recognised as coming through a live public share. No implementation exists yet.
