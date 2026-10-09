// Package waka is the server library every app server embeds. It verifies
// hub tokens, issues the server's own sessions, and owns grants, links and
// the permission check. It holds no tunnel code.
//
// Mount Handler at "/waka/" and "/.well-known/waka-server", then use
// Principal, User and Has in the app's own routes.
package waka

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Dialect string

const (
	SQLite   Dialect = "sqlite"
	Postgres Dialect = "postgres"
)

// Resource names something an app can share: an album, a realm, a notebook.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Joinable is something a user could join but has not.
type Joinable struct {
	Resource Resource `json:"resource"`
	Title    string   `json:"title"`
	Roles    []string `json:"roles"`
	// Info is whatever else the app wants a directory to show (a description,
	// an icon, a member count). The library passes it through untouched.
	Info any `json:"info,omitempty"`
}

// SignIn is who may sign in to the server.
type SignIn string

const (
	// SignInOpen lets in any account of the app. The default.
	SignInOpen SignIn = "open"
	// SignInInvite lets in only people with a grant here (pending ones
	// included), the owner and Admins. Joining through a link is always
	// possible.
	SignInInvite SignIn = "invite"
)

type Config struct {
	// Issuer is the hub this server belongs to. It is a config value so a
	// server can be pointed at another hub.
	Issuer string
	// TrustedIssuers are the hubs whose tokens are accepted. Default: Issuer.
	TrustedIssuers []string
	// ServerID and ServerSecret come from registering the server on the hub.
	ServerID     string
	ServerSecret string

	Name string
	App  string
	// PublicURL is the address clients reach this server at.
	PublicURL string
	// Address returns the address to register in the hub's directory.
	// Default: PublicURL. Cosmos supplies its own here.
	Address func() string
	// Shares opens public links somewhere other than this server's own
	// hostname. Default: links are stored locally. Cosmos plugs in here.
	Shares ShareOpener
	// LinkPath is where the app serves its link landing page. Default "/s/".
	LinkPath string

	DB      *sql.DB
	Dialect Dialect

	// SessionTTL is the fixed life of a server session. Default 7 days.
	SessionTTL time.Duration

	// Roles returns the roles a resource offers, each with the permissions
	// it carries. The app owns this list and may change it at any time; the
	// library only records which role names each grant holds. Default:
	// DefaultRoles for every resource.
	Roles func(ctx context.Context, res Resource) ([]RoleDef, error)
	// SharePerm is the permission that allows creating links and sharing by
	// handle, and seeing and revoking one's own links and invites. Default
	// "share".
	SharePerm string
	// ManagePerm is the permission that allows changing and revoking other
	// people's grants and links. Default "manage".
	ManagePerm string
	// AllowLink decides whether a link of one kind (public, or for accounts)
	// may carry these roles on a resource. Default: any role that may be
	// handed out, on either kind.
	AllowLink func(ctx context.Context, res Resource, public bool, roles []string) bool
	// AdminPower gives the server's owner and Admins every permission on
	// every resource. Default off.
	AdminPower bool

	// Admins are the handles, on Issuer and as seen on this server, of people
	// who run this server besides its owner. The owner, the account that
	// registered the server on the hub, needs no listing; this is the
	// recovery override.
	Admins []string
	// SignIn is who may sign in. Default SignInOpen.
	SignIn SignIn
	// AllowUser is an extra check on every sign-in, link joins included.
	// Default: everyone SignIn lets in.
	AllowUser func(ctx context.Context, u *User) bool

	// Parent returns the resource another one inherits access from.
	Parent func(ctx context.Context, res Resource) (Resource, bool)
	// Describe returns a resource's display title.
	Describe func(ctx context.Context, res Resource) (string, bool)
	// Joinable lists what the user could join here but has not.
	Joinable func(ctx context.Context, u *User) ([]Joinable, error)
	// CanJoin returns the roles a user gets by joining an open resource.
	CanJoin func(ctx context.Context, u *User, res Resource) ([]string, bool)
	// AllowGrant is asked before a user gains access to a resource other than
	// through the app's own Grant or SetRoles: a share by handle, a link
	// claimed or joined through, an open resource joined, a pending share
	// accepted. Returning false refuses it with ErrForbidden. Default: allowed.
	// It is where an app keeps someone it has shut out of one resource (a ban
	// from one community) from coming back in by a link.
	AllowGrant func(ctx context.Context, u *User, res Resource) bool
	// OnGrant is called after every change to a grant has been written. It
	// runs synchronously, in the request that made the change; an error is
	// logged and does not undo the change.
	OnGrant func(ctx context.Context, change GrantChange) error

	HTTPClient *http.Client
}

type Waka struct {
	cfg        Config
	db         *sql.DB
	keys       *keyCache
	sessionKey []byte
	attempts   *attempts

	// signIn is Config.SignIn, changeable at runtime with SetSignIn.
	signIn atomic.Value
}

func New(ctx context.Context, cfg Config) (*Waka, error) {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if cfg.Issuer == "" || cfg.ServerID == "" || cfg.DB == nil {
		return nil, errors.New("waka: Issuer, ServerID and DB are required")
	}
	if len(cfg.TrustedIssuers) == 0 {
		cfg.TrustedIssuers = []string{cfg.Issuer}
	}
	for i, iss := range cfg.TrustedIssuers {
		cfg.TrustedIssuers[i] = strings.TrimRight(iss, "/")
	}
	if cfg.Dialect == "" {
		cfg.Dialect = SQLite
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 7 * 24 * time.Hour
	}
	if cfg.SharePerm == "" {
		cfg.SharePerm = "share"
	}
	if cfg.ManagePerm == "" {
		cfg.ManagePerm = "manage"
	}
	switch cfg.SignIn {
	case "":
		cfg.SignIn = SignInOpen
	case SignInOpen, SignInInvite:
	default:
		return nil, errors.New("waka: SignIn must be SignInOpen or SignInInvite")
	}
	if cfg.LinkPath == "" {
		cfg.LinkPath = "/s/"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	w := &Waka{cfg: cfg, db: cfg.DB, keys: newKeyCache(cfg.HTTPClient), attempts: newAttempts()}
	w.signIn.Store(cfg.SignIn)
	if err := w.migrate(ctx); err != nil {
		return nil, err
	}
	return w, nil
}

// SetSignIn changes who may sign in, for an app whose setting is edited while
// it runs. Sessions already issued are not affected.
func (w *Waka) SetSignIn(s SignIn) error {
	if s != SignInOpen && s != SignInInvite {
		return errors.New("waka: SignIn must be SignInOpen or SignInInvite")
	}
	w.signIn.Store(s)
	return nil
}

// SignInMode returns who may sign in now.
func (w *Waka) SignInMode() SignIn { return w.signIn.Load().(SignIn) }

// schemaVersion goes up with every change to the waka_ tables.
const schemaVersion = "2"

func (w *Waka) migrate(ctx context.Context) error {
	blob := "BLOB"
	if w.cfg.Dialect == Postgres {
		blob = "BYTEA"
	}
	// Nothing is deployed with real users yet, so tables from an older
	// schema are dropped rather than migrated.
	if _, err := w.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS waka_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		return err
	}
	var version string
	w.db.QueryRowContext(ctx, `SELECT v FROM waka_meta WHERE k = 'schema'`).Scan(&version)
	if version != schemaVersion {
		for _, t := range []string{"waka_grants", "waka_bans", "waka_users"} {
			if _, err := w.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+t); err != nil {
				return err
			}
		}
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS waka_users (
			id TEXT PRIMARY KEY,
			issuer TEXT NOT NULL, subject TEXT NOT NULL,
			handle TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', bio TEXT NOT NULL DEFAULT '',
			picture TEXT NOT NULL DEFAULT '',
			avatar ` + blob + `, avatar_type TEXT NOT NULL DEFAULT '', avatar_version BIGINT NOT NULL DEFAULT 0,
			profile_version BIGINT NOT NULL DEFAULT 0,
			created_at BIGINT NOT NULL, last_login_at BIGINT NOT NULL DEFAULT 0,
			session_gen BIGINT NOT NULL DEFAULT 0,
			owner BOOLEAN NOT NULL DEFAULT FALSE,
			UNIQUE (issuer, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS waka_bans (
			issuer TEXT NOT NULL, subject TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL,
			PRIMARY KEY (issuer, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS waka_grants (
			id TEXT PRIMARY KEY,
			resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
			kind TEXT NOT NULL, user_id TEXT NOT NULL DEFAULT '',
			roles TEXT NOT NULL, status TEXT NOT NULL,
			created_by TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
			lookup TEXT NOT NULL DEFAULT '', secret_hash TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL DEFAULT '',
			expires_at BIGINT NOT NULL DEFAULT 0, revoked_at BIGINT NOT NULL DEFAULT 0,
			max_uses BIGINT NOT NULL DEFAULT 0, uses BIGINT NOT NULL DEFAULT 0,
			external_id TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
			public BOOLEAN NOT NULL DEFAULT FALSE
		)`,
		`CREATE INDEX IF NOT EXISTS waka_grants_resource ON waka_grants (resource_type, resource_id)`,
		`CREATE INDEX IF NOT EXISTS waka_grants_user ON waka_grants (user_id)`,
		`CREATE INDEX IF NOT EXISTS waka_grants_lookup ON waka_grants (lookup)`,
	}
	for _, stmt := range stmts {
		if _, err := w.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if version != schemaVersion {
		if _, err := w.db.ExecContext(ctx, w.q(`INSERT INTO waka_meta (k, v) VALUES ('schema', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`), schemaVersion); err != nil {
			return err
		}
	}

	// The key that signs this server's own session tokens.
	var stored string
	err := w.db.QueryRowContext(ctx, w.q(`SELECT v FROM waka_meta WHERE k = 'session_key'`)).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		key := make([]byte, 32)
		rand.Read(key)
		stored = base64.StdEncoding.EncodeToString(key)
		if _, err := w.db.ExecContext(ctx, w.q(`INSERT INTO waka_meta (k, v) VALUES ('session_key', ?) ON CONFLICT (k) DO NOTHING`), stored); err != nil {
			return err
		}
		err = w.db.QueryRowContext(ctx, w.q(`SELECT v FROM waka_meta WHERE k = 'session_key'`)).Scan(&stored)
	}
	if err != nil {
		return err
	}
	w.sessionKey, err = base64.StdEncoding.DecodeString(stored)
	return err
}

// q rewrites "?" placeholders for the configured database.
func (w *Waka) q(query string) string {
	if w.cfg.Dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (w *Waka) address() string {
	if w.cfg.Address != nil {
		return strings.TrimRight(w.cfg.Address(), "/")
	}
	return w.cfg.PublicURL
}

// --- small helpers ---

func now() int64 { return time.Now().Unix() }

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return idEncoding.EncodeToString(b)
}

func newSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
