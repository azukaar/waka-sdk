package waka

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User is a Waka account as this server knows it. ID is local to the server
// and is what apps key their own data on; the identity is (Issuer, Subject).
type User struct {
	ID      string `json:"id"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Handle  string `json:"handle"`
	Name    string `json:"name"`
	Bio     string `json:"bio"`
	// Avatar is the path of this server's own copy, or "".
	Avatar string `json:"avatar"`

	picture        string
	profileVersion int64
	sessionGen     int64
	owner          bool
}

// Principal is who is asking: a signed-in user, or the holder of a link.
type Principal struct {
	User *User
	Link *Grant
}

var (
	ErrBanned       = errors.New("waka: this account is banned from this server")
	ErrNotAllowed   = errors.New("waka: this account may not sign in to this server")
	ErrUserNotFound = errors.New("waka: no such user")
	// ErrNoSession: the session is malformed, expired or was ended.
	ErrNoSession = errors.New("waka: no valid session")
)

const userCols = `id, issuer, subject, handle, name, bio, picture, avatar_version, profile_version, session_gen, owner`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var avatarVersion int64
	if err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Handle, &u.Name, &u.Bio, &u.picture, &avatarVersion, &u.profileVersion, &u.sessionGen, &u.owner); err != nil {
		return nil, err
	}
	if avatarVersion > 0 {
		u.Avatar = "/waka/users/" + u.ID + "/avatar?v=" + strconv.FormatInt(avatarVersion, 10)
	}
	return u, nil
}

// GetUser returns a user by local ID.
func (w *Waka) GetUser(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(w.db.QueryRowContext(ctx, w.q(`SELECT `+userCols+` FROM waka_users WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

func (w *Waka) userByIdentity(ctx context.Context, issuer, subject string) (*User, error) {
	u, err := scanUser(w.db.QueryRowContext(ctx, w.q(`SELECT `+userCols+` FROM waka_users WHERE issuer = ? AND subject = ?`), issuer, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

// ensureUser returns the local user for an identity, creating a stub if this
// server has not seen them yet (someone shared with before their first
// login). The handle and name are only used for a new row.
func (w *Waka) ensureUser(ctx context.Context, issuer, subject, handle, name string) (*User, error) {
	if _, err := w.db.ExecContext(ctx, w.q(`INSERT INTO waka_users (id, issuer, subject, handle, name, created_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (issuer, subject) DO NOTHING`), newID(), issuer, subject, handle, name, now()); err != nil {
		return nil, err
	}
	return w.userByIdentity(ctx, issuer, subject)
}

func (w *Waka) isBanned(ctx context.Context, issuer, subject string) bool {
	var one int
	return w.db.QueryRowContext(ctx, w.q(`SELECT 1 FROM waka_bans WHERE issuer = ? AND subject = ?`), issuer, subject).Scan(&one) == nil
}

// IsOwner reports whether the user registered this server on the hub. The
// hub says so in the login token, and it is recorded at every login.
func (w *Waka) IsOwner(u *User) bool {
	return u != nil && u.Issuer == w.cfg.Issuer && u.owner
}

// IsAdmin reports whether the user runs this server: its owner, or one of
// the handles in Config.Admins, which stays as a recovery override.
func (w *Waka) IsAdmin(u *User) bool {
	return w.IsOwner(u) || (u != nil && u.Issuer == w.cfg.Issuer && slices.Contains(w.cfg.Admins, u.Handle))
}

// HasAnyGrant reports whether anything on this server was shared with the
// user and not declined. It is what SignInInvite checks.
func (w *Waka) HasAnyGrant(ctx context.Context, userID string) bool {
	var one int
	return w.db.QueryRowContext(ctx, w.q(`SELECT 1 FROM waka_grants WHERE kind = 'user' AND user_id = ? AND status <> 'declined' LIMIT 1`), userID).Scan(&one) == nil
}

// Ban stops an identity from using this server and ends its sessions.
func (w *Waka) Ban(ctx context.Context, u *User, reason string) error {
	if _, err := w.db.ExecContext(ctx, w.q(`INSERT INTO waka_bans (issuer, subject, reason, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (issuer, subject) DO NOTHING`), u.Issuer, u.Subject, reason, now()); err != nil {
		return err
	}
	return w.EndSessions(ctx, u)
}

// EndSessions ends every session the user has on this server. They can
// sign in again.
func (w *Waka) EndSessions(ctx context.Context, u *User) error {
	// A session names the generation it was issued in; this retires them all.
	_, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_users SET session_gen = session_gen + 1 WHERE id = ?`), u.ID)
	return err
}

// Unban lets an identity sign in again. Sessions ended by the ban stay ended.
func (w *Waka) Unban(ctx context.Context, u *User) error {
	_, err := w.db.ExecContext(ctx, w.q(`DELETE FROM waka_bans WHERE issuer = ? AND subject = ?`), u.Issuer, u.Subject)
	return err
}

// --- sessions ---

// Session is this server's own token for a signed-in user or link holder.
type Session struct {
	Token     string `json:"session"`
	ExpiresAt int64  `json:"expires_at"`
	User      *User  `json:"user,omitempty"`
}

type sessionClaims struct {
	Type string `json:"typ"`
	// The Waka identity the session belongs to.
	WakaIssuer  string `json:"wiss,omitempty"`
	WakaSubject string `json:"wsub,omitempty"`
	// Gen is the user's session generation when it was issued.
	Gen     int64  `json:"gen,omitempty"`
	GrantID string `json:"gid,omitempty"`
	jwt.RegisteredClaims
}

func (w *Waka) signSession(c sessionClaims, ttl time.Duration) (*Session, error) {
	t := time.Now()
	c.IssuedAt = jwt.NewNumericDate(t)
	c.ExpiresAt = jwt.NewNumericDate(t.Add(ttl))
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(w.sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{Token: tok, ExpiresAt: c.ExpiresAt.Unix()}, nil
}

// Login turns a hub token into a server session. With JoinLink, it is the
// only way a user session starts. The profile copy is refreshed from the
// token, then Config.SignIn and Config.AllowUser decide.
func (w *Waka) Login(ctx context.Context, hubToken string) (*Session, error) {
	return w.login(ctx, hubToken, false)
}

// login signs a user in. Joining through a link skips Config.SignIn.
func (w *Waka) login(ctx context.Context, hubToken string, viaLink bool) (*Session, error) {
	claims, err := w.VerifyHubToken(ctx, hubToken)
	if err != nil {
		return nil, err
	}
	if w.isBanned(ctx, claims.Issuer, claims.Subject) {
		return nil, ErrBanned
	}
	u, err := w.ensureUser(ctx, claims.Issuer, claims.Subject, claims.Handle, claims.Name)
	if err != nil {
		return nil, err
	}
	// Only the hub that issued the identity can say who owns this server.
	owner := claims.Owner && claims.Issuer == w.cfg.Issuer
	if _, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_users SET handle = ?, name = ?, bio = ?, profile_version = ?, owner = ?, last_login_at = ? WHERE id = ?`),
		claims.Handle, claims.Name, claims.Bio, claims.ProfileVersion, owner, now(), u.ID); err != nil {
		return nil, err
	}
	if claims.Picture != u.picture {
		w.copyAvatar(ctx, u.ID, claims.Issuer, claims.Picture)
	}
	if u, err = w.GetUser(ctx, u.ID); err != nil {
		return nil, err
	}
	if !viaLink && w.SignInMode() == SignInInvite && !w.IsAdmin(u) && !w.HasAnyGrant(ctx, u.ID) {
		return nil, ErrNotAllowed
	}
	if w.cfg.AllowUser != nil && !w.cfg.AllowUser(ctx, u) {
		return nil, ErrNotAllowed
	}
	s, err := w.signSession(sessionClaims{
		Type: "user", WakaIssuer: u.Issuer, WakaSubject: u.Subject, Gen: u.sessionGen,
		RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID},
	}, w.cfg.SessionTTL)
	if err != nil {
		return nil, err
	}
	s.User = u
	return s, nil
}

const maxAvatarBytes = 1 << 20

// copyAvatar keeps this server's own copy of the avatar, so that showing a
// profile never calls the hub. Failure is not fatal: the old copy stays.
func (w *Waka) copyAvatar(ctx context.Context, userID, issuer, picture string) {
	if picture == "" {
		w.db.ExecContext(ctx, w.q(`UPDATE waka_users SET picture = '', avatar = NULL, avatar_type = '', avatar_version = 0 WHERE id = ?`), userID)
		return
	}
	// Only ever fetch from the hub that signed the token.
	if !strings.HasPrefix(picture, issuer+"/") {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, picture, nil)
	if err != nil {
		return
	}
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAvatarBytes+1))
	ctype := http.DetectContentType(data)
	if err != nil || resp.StatusCode != http.StatusOK || len(data) > maxAvatarBytes || !strings.HasPrefix(ctype, "image/") {
		return
	}
	w.db.ExecContext(ctx, w.q(`UPDATE waka_users SET picture = ?, avatar = ?, avatar_type = ?, avatar_version = avatar_version + 1 WHERE id = ?`),
		picture, data, ctype, userID)
}

const sessionCookie = "waka_session"

func sessionToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return h[7:]
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// Principal resolves who is making a request, or nil. Bans, session
// revocation and link expiry are re-read every time.
func (w *Waka) Principal(r *http.Request) *Principal {
	ctx := r.Context()
	if w.cfg.Shares != nil {
		if externalID, ok := w.cfg.Shares.Verify(r); ok {
			g, err := w.scanGrant(w.db.QueryRowContext(ctx, w.q(`SELECT `+grantCols+` FROM waka_grants WHERE kind = 'link' AND external_id = ?`), externalID))
			if err == nil && g.alive() && g.Public {
				return &Principal{Link: g}
			}
			return nil
		}
	}
	raw := sessionToken(r)
	if raw == "" {
		return nil
	}
	p, _ := w.SessionPrincipal(ctx, raw)
	return p
}

// SessionPrincipal checks a session given as a string, for protocols that
// carry it in a message rather than a header: a gateway's IDENTIFY, a
// Hocuspocus onAuthenticate. The checks are the same as for a request:
// ErrNoSession for one that is malformed, expired or ended, ErrBanned for a
// banned user, ErrLinkDead for a link that was revoked or ran out.
func (w *Waka) SessionPrincipal(ctx context.Context, raw string) (*Principal, error) {
	claims := &sessionClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return w.sessionKey, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired()); err != nil {
		return nil, ErrNoSession
	}
	switch claims.Type {
	case "user":
		u, err := w.GetUser(ctx, claims.Subject)
		if err != nil {
			return nil, ErrNoSession
		}
		if w.isBanned(ctx, u.Issuer, u.Subject) {
			return nil, ErrBanned
		}
		if claims.Gen != u.sessionGen {
			return nil, ErrNoSession
		}
		return &Principal{User: u}, nil
	case "link":
		g, err := w.getGrant(ctx, claims.GrantID)
		if err != nil || g.Kind != KindLink {
			return nil, ErrNoSession
		}
		if !g.alive() || !g.Public {
			return nil, ErrLinkDead
		}
		return &Principal{Link: g}, nil
	}
	return nil, ErrNoSession
}

// User returns the signed-in user making a request, or nil.
func (w *Waka) User(r *http.Request) *User {
	if p := w.Principal(r); p != nil {
		return p.User
	}
	return nil
}

// RequireUser wraps a handler that needs a signed-in user.
func (w *Waka) RequireUser(h func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		u := w.User(r)
		if u == nil {
			writeErr(rw, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(rw, r, u)
	}
}

// CORS lets clients on other origins (desktop apps, hosted web apps) call
// the server with a bearer token. Cookies are never sent cross-origin.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(rw, r)
	})
}
