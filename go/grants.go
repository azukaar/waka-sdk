package waka

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A share is one record: resource, principal, roles, status. The principal
// is a user or a link. Ownership is a grant like any other, holding the
// owner role, so "what have I joined" and "what may I do" are answered by
// one table.
const (
	KindUser = "user"
	KindLink = "link"

	StatusPending  = "pending"
	StatusAccepted = "accepted"
	StatusDeclined = "declined"
)

type Grant struct {
	ID        string   `json:"id"`
	Resource  Resource `json:"resource"`
	Kind      string   `json:"kind"`
	UserID    string   `json:"user_id,omitempty"`
	Roles     []string `json:"roles"`
	Status    string   `json:"status"`
	CreatedBy string   `json:"created_by,omitempty"`
	CreatedAt int64    `json:"created_at"`

	// Link grants only. LinkID is public; the secret is never stored.
	LinkID      string `json:"link_id,omitempty"`
	Public      bool   `json:"public,omitempty"`
	Label       string `json:"label,omitempty"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	RevokedAt   int64  `json:"revoked_at,omitempty"`
	MaxUses     int64  `json:"max_uses,omitempty"`
	Uses        int64  `json:"uses,omitempty"`
	HasPassword bool   `json:"has_password,omitempty"`

	secretHash   string
	passwordHash string
	externalID   string
}

func (g *Grant) alive() bool {
	return g.RevokedAt == 0 && (g.ExpiresAt == 0 || g.ExpiresAt > now())
}

var (
	ErrForbidden    = errors.New("waka: not allowed")
	ErrNoSuchGrant  = errors.New("waka: no such grant")
	ErrBadRole      = errors.New("waka: unknown role")
	ErrLinkDead     = errors.New("waka: this link is no longer valid")
	ErrAccountsOnly = errors.New("waka: this link is for Waka accounts only")
	ErrBadPassword  = errors.New("waka: wrong password")
	ErrTooManyTries = errors.New("waka: too many attempts, try again in a minute")
)

// --- grant changes ---

// ChangeType says what happened to a grant.
type ChangeType string

const (
	// GrantCreated: a share by handle, pending until answered, or a new link.
	GrantCreated ChangeType = "created"
	// GrantGranted: the app's own Grant call.
	GrantGranted  ChangeType = "granted"
	GrantAccepted ChangeType = "accepted"
	// GrantJoined: an open resource joined through Config.CanJoin.
	GrantJoined ChangeType = "joined"
	// GrantClaimed: a link turned into the user's own grant.
	GrantClaimed  ChangeType = "claimed"
	GrantDeclined ChangeType = "declined"
	GrantLeft     ChangeType = "left"
	// GrantRevoked: a user grant removed or a link killed by someone else.
	GrantRevoked      ChangeType = "revoked"
	GrantRolesChanged ChangeType = "roles_changed"
	// ResourceDeleted: every grant on the resource is gone. Before and After
	// are nil.
	ResourceDeleted ChangeType = "resource_deleted"
)

// GrantChange is passed to Config.OnGrant after a change is written.
type GrantChange struct {
	Type     ChangeType
	Resource Resource
	// Before is nil for a new grant, After is nil for a removed one.
	Before, After *Grant
	// By is who acted, or nil when the app called the library directly
	// without naming anyone.
	By *User
}

func (w *Waka) changed(ctx context.Context, t ChangeType, res Resource, before, after *Grant, by string) {
	if w.cfg.OnGrant == nil {
		return
	}
	c := GrantChange{Type: t, Resource: res, Before: before, After: after}
	if by != "" {
		c.By, _ = w.GetUser(ctx, by)
	}
	if err := w.cfg.OnGrant(ctx, c); err != nil {
		log.Printf("waka: OnGrant %s on %s %s: %v", t, res.Type, res.ID, err)
	}
}

// --- storage ---

const grantCols = `id, resource_type, resource_id, kind, user_id, roles, status, created_by, created_at,
	lookup, secret_hash, password_hash, expires_at, revoked_at, max_uses, uses, external_id, label, public`

func encodeRoles(roles []string) string {
	data, _ := json.Marshal(normRoles(roles))
	return string(data)
}

func decodeRoles(raw string) []string {
	roles := []string{}
	json.Unmarshal([]byte(raw), &roles)
	return roles
}

func (w *Waka) scanGrant(row interface{ Scan(...any) error }) (*Grant, error) {
	g := &Grant{}
	var roles string
	err := row.Scan(&g.ID, &g.Resource.Type, &g.Resource.ID, &g.Kind, &g.UserID, &roles, &g.Status, &g.CreatedBy, &g.CreatedAt,
		&g.LinkID, &g.secretHash, &g.passwordHash, &g.ExpiresAt, &g.RevokedAt, &g.MaxUses, &g.Uses, &g.externalID, &g.Label, &g.Public)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSuchGrant
	}
	g.Roles = decodeRoles(roles)
	g.HasPassword = g.passwordHash != ""
	return g, err
}

func (w *Waka) getGrant(ctx context.Context, id string) (*Grant, error) {
	return w.scanGrant(w.db.QueryRowContext(ctx, w.q(`SELECT `+grantCols+` FROM waka_grants WHERE id = ?`), id))
}

func (w *Waka) queryGrants(ctx context.Context, where string, args ...any) ([]*Grant, error) {
	rows, err := w.db.QueryContext(ctx, w.q(`SELECT `+grantCols+` FROM waka_grants WHERE `+where+` ORDER BY created_at`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Grant{}
	for rows.Next() {
		g, err := w.scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GrantOf returns the one grant a user holds on a resource, in whatever
// status, or ErrNoSuchGrant.
func (w *Waka) GrantOf(ctx context.Context, res Resource, userID string) (*Grant, error) {
	return w.userGrant(ctx, res, userID)
}

func (w *Waka) userGrant(ctx context.Context, res Resource, userID string) (*Grant, error) {
	return w.scanGrant(w.db.QueryRowContext(ctx, w.q(`SELECT `+grantCols+` FROM waka_grants
		WHERE kind = 'user' AND user_id = ? AND resource_type = ? AND resource_id = ?`), userID, res.Type, res.ID))
}

// Joined lists what a user has joined: what they own and what they accepted.
func (w *Waka) Joined(ctx context.Context, userID string) ([]*Grant, error) {
	return w.queryGrants(ctx, `kind = 'user' AND user_id = ? AND status = 'accepted'`, userID)
}

// Invites lists what has been shared with a user and not answered yet.
func (w *Waka) Invites(ctx context.Context, userID string) ([]*Grant, error) {
	return w.queryGrants(ctx, `kind = 'user' AND user_id = ? AND status = 'pending'`, userID)
}

// GrantsOn lists every grant and live link on a resource.
func (w *Waka) GrantsOn(ctx context.Context, res Resource) ([]*Grant, error) {
	return w.queryGrants(ctx, `resource_type = ? AND resource_id = ? AND revoked_at = 0`, res.Type, res.ID)
}

// addRoles adds roles to the single grant a user has on a resource,
// creating it if needed. An accepted grant stays accepted; a declined one
// is asked again. It returns the grant before and after.
func (w *Waka) addRoles(ctx context.Context, res Resource, userID string, roles []string, status, by string) (before, after *Grant, err error) {
	before, err = w.userGrant(ctx, res, userID)
	switch {
	case err == nil:
		if before.Status == StatusAccepted {
			status = StatusAccepted
		}
		if before.Status != StatusDeclined {
			roles = unionRoles(before.Roles, roles)
		}
		if _, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_grants SET roles = ?, status = ?, updated_at = ? WHERE id = ?`),
			encodeRoles(roles), status, now(), before.ID); err != nil {
			return nil, nil, err
		}
		after, err = w.getGrant(ctx, before.ID)
		return before, after, err
	case errors.Is(err, ErrNoSuchGrant):
		id := newID()
		if _, err := w.db.ExecContext(ctx, w.q(`INSERT INTO waka_grants (id, resource_type, resource_id, kind, user_id, roles, status, created_by, created_at, updated_at)
			VALUES (?, ?, ?, 'user', ?, ?, ?, ?, ?, ?)`), id, res.Type, res.ID, userID, encodeRoles(roles), status, by, now(), now()); err != nil {
			return nil, nil, err
		}
		after, err = w.getGrant(ctx, id)
		return nil, after, err
	}
	return nil, nil, err
}

// --- what the app does directly ---

// Grant gives a user roles on a resource, already accepted, adding to any
// they hold. Apps call it when a resource is created (with the owner role)
// and for anything their own rules decide. Nothing is checked.
func (w *Waka) Grant(ctx context.Context, res Resource, userID string, roles []string, by string) (*Grant, error) {
	return w.grantAs(ctx, GrantGranted, res, userID, roles, by)
}

func (w *Waka) grantAs(ctx context.Context, t ChangeType, res Resource, userID string, roles []string, by string) (*Grant, error) {
	if len(normRoles(roles)) == 0 {
		return nil, ErrBadRole
	}
	before, after, err := w.addRoles(ctx, res, userID, roles, StatusAccepted, by)
	if err != nil {
		return nil, err
	}
	w.changed(ctx, t, res, before, after, by)
	return after, nil
}

// SetRoles replaces the roles of a grant, owner role included: for an
// ownership transfer or the app's own role editor. Nothing is checked.
func (w *Waka) SetRoles(ctx context.Context, g *Grant, roles []string, by string) (*Grant, error) {
	roles = normRoles(roles)
	if len(roles) == 0 {
		return nil, ErrBadRole
	}
	if _, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_grants SET roles = ?, updated_at = ? WHERE id = ?`), encodeRoles(roles), now(), g.ID); err != nil {
		return nil, err
	}
	after, err := w.getGrant(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	w.changed(ctx, GrantRolesChanged, g.Resource, g, after, by)
	return after, nil
}

// Revoke removes a user's grant or kills a link. Nothing is checked.
func (w *Waka) Revoke(ctx context.Context, g *Grant) error {
	return w.revoke(ctx, GrantRevoked, g, "")
}

func (w *Waka) revoke(ctx context.Context, t ChangeType, g *Grant, by string) error {
	if g.Kind == KindLink {
		if g.externalID != "" && w.cfg.Shares != nil {
			if err := w.cfg.Shares.Close(ctx, g.externalID); err != nil {
				return err
			}
		}
		if _, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_grants SET revoked_at = ? WHERE id = ?`), now(), g.ID); err != nil {
			return err
		}
	} else if _, err := w.db.ExecContext(ctx, w.q(`DELETE FROM waka_grants WHERE id = ?`), g.ID); err != nil {
		return err
	}
	w.changed(ctx, t, g.Resource, g, nil, by)
	return nil
}

// DeleteResource removes every grant on a resource. Apps call it when the
// resource itself is deleted.
func (w *Waka) DeleteResource(ctx context.Context, res Resource) error {
	if w.cfg.Shares != nil {
		links, _ := w.queryGrants(ctx, `resource_type = ? AND resource_id = ? AND kind = 'link' AND external_id <> ''`, res.Type, res.ID)
		for _, g := range links {
			w.cfg.Shares.Close(ctx, g.externalID)
		}
	}
	if _, err := w.db.ExecContext(ctx, w.q(`DELETE FROM waka_grants WHERE resource_type = ? AND resource_id = ?`), res.Type, res.ID); err != nil {
		return err
	}
	w.changed(ctx, ResourceDeleted, res, nil, nil, "")
	return nil
}

// --- what a user does to their own grants ---

func (w *Waka) ownGrant(ctx context.Context, u *User, grantID string) (*Grant, error) {
	g, err := w.getGrant(ctx, grantID)
	if err != nil || g.Kind != KindUser || g.UserID != u.ID {
		return nil, ErrNoSuchGrant
	}
	return g, nil
}

func (w *Waka) setStatus(ctx context.Context, t ChangeType, g *Grant, status, by string) (*Grant, error) {
	if _, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_grants SET status = ?, updated_at = ? WHERE id = ?`), status, now(), g.ID); err != nil {
		return nil, err
	}
	after, err := w.getGrant(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	w.changed(ctx, t, g.Resource, g, after, by)
	return after, nil
}

// ErrNotApplicable: the action does not apply to the grant in its state.
var ErrNotApplicable = errors.New("waka: that action does not apply to this grant")

// Accept accepts a pending grant shared with the user.
func (w *Waka) Accept(ctx context.Context, u *User, grantID string) (*Grant, error) {
	g, err := w.ownGrant(ctx, u, grantID)
	if err != nil {
		return nil, err
	}
	if g.Status != StatusPending {
		return nil, ErrNotApplicable
	}
	if !w.grantAllowed(ctx, u, g.Resource) {
		return nil, ErrForbidden
	}
	return w.setStatus(ctx, GrantAccepted, g, StatusAccepted, u.ID)
}

// Decline declines a pending grant shared with the user.
func (w *Waka) Decline(ctx context.Context, u *User, grantID string) error {
	g, err := w.ownGrant(ctx, u, grantID)
	if err != nil {
		return err
	}
	if g.Status != StatusPending {
		return ErrNotApplicable
	}
	_, err = w.setStatus(ctx, GrantDeclined, g, StatusDeclined, u.ID)
	return err
}

// Leave gives up an accepted grant. An owner cannot leave.
func (w *Waka) Leave(ctx context.Context, u *User, grantID string) error {
	g, err := w.ownGrant(ctx, u, grantID)
	if err != nil {
		return err
	}
	defs, err := w.RolesFor(ctx, g.Resource)
	if err != nil {
		return err
	}
	if g.Status != StatusAccepted || holdsOwner(defs, g.Roles) {
		return ErrNotApplicable
	}
	return w.revoke(ctx, GrantLeft, g, u.ID)
}

// Join joins an open resource with the roles Config.CanJoin gives.
func (w *Waka) Join(ctx context.Context, u *User, res Resource) (*Grant, error) {
	if w.cfg.CanJoin == nil {
		return nil, ErrForbidden
	}
	roles, ok := w.cfg.CanJoin(ctx, u, res)
	if !ok || !w.grantAllowed(ctx, u, res) {
		return nil, ErrForbidden
	}
	return w.grantAs(ctx, GrantJoined, res, u.ID, roles, u.ID)
}

// --- what a user does to other people's access ---

// Share gives a Waka account roles on a resource and announces it through
// their hub inbox. The grant stays pending until they accept it here; an
// account that already has a grant gets the roles added to it.
// delivered is false when the grant was made but the hub refused or could
// not take the invite; the recipient still finds it when they sign in.
//
// by must hold SharePerm, every permission of the roles, and every
// permission the recipient already holds.
func (w *Waka) Share(ctx context.Context, by *User, res Resource, handle string, roles []string) (g *Grant, delivered bool, err error) {
	roles = normRoles(roles)
	m, err := w.sharer(ctx, by, res, roles)
	if err != nil {
		return nil, false, err
	}
	target, err := w.LookupUser(ctx, handle)
	if err != nil {
		return nil, false, err
	}
	if w.isBanned(ctx, w.cfg.Issuer, target.ID) {
		return nil, false, ErrBanned
	}
	u, err := w.ensureUser(ctx, w.cfg.Issuer, target.ID, target.Handle, target.Name)
	if err != nil {
		return nil, false, err
	}
	return w.shareWith(ctx, m, by, res, u, roles)
}

// ShareUser is Share for someone this server already knows, named by local
// user ID rather than by handle, so the hub is only asked to deliver the
// invite. Apps use it where the person was picked from their own data (a
// direct message started from a member list), not typed in.
func (w *Waka) ShareUser(ctx context.Context, by *User, res Resource, userID string, roles []string) (g *Grant, delivered bool, err error) {
	roles = normRoles(roles)
	m, err := w.sharer(ctx, by, res, roles)
	if err != nil {
		return nil, false, err
	}
	u, err := w.GetUser(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	if w.isBanned(ctx, u.Issuer, u.Subject) {
		return nil, false, ErrBanned
	}
	return w.shareWith(ctx, m, by, res, u, roles)
}

// sharer checks that by may share these roles on the resource.
func (w *Waka) sharer(ctx context.Context, by *User, res Resource, roles []string) (*manager, error) {
	m, err := w.managerFor(ctx, by, res)
	if err != nil {
		return nil, err
	}
	if !m.canShare() {
		return nil, ErrForbidden
	}
	if err := checkAssign(m.mine.perms, m.defs, roles); err != nil {
		return nil, err
	}
	return m, nil
}

func (w *Waka) shareWith(ctx context.Context, m *manager, by *User, res Resource, u *User, roles []string) (*Grant, bool, error) {
	if u.ID == by.ID || !w.grantAllowed(ctx, u, res) {
		return nil, false, ErrForbidden
	}
	// Nobody changes the grant of someone holding more than they do. A
	// declined grant is asked again as if new.
	if existing, err := w.userGrant(ctx, res, u.ID); err == nil && existing.Status != StatusDeclined {
		if err := m.canChange(ctx, existing); err != nil {
			return nil, false, err
		}
	} else if theirs, err := w.access(ctx, &Principal{User: u}, res); err != nil || !m.mine.perms.covers(theirs.perms) {
		return nil, false, ErrForbidden
	}
	before, g, err := w.addRoles(ctx, res, u.ID, roles, StatusPending, by.ID)
	if err != nil {
		return nil, false, err
	}
	t := GrantCreated
	if before != nil && before.Status != StatusDeclined {
		t = GrantRolesChanged
	}
	w.changed(ctx, t, res, before, g, by.ID)
	if g.Status != StatusPending || by.Issuer != w.cfg.Issuer || u.Issuer != w.cfg.Issuer {
		return g, false, nil
	}
	title, _ := w.describe(ctx, res)
	err = w.send(ctx, "invite", u.Subject, by.Subject, g.ID, map[string]any{
		"type":     "invite",
		"server":   w.serverInfo(),
		"resource": map[string]string{"type": res.Type, "id": res.ID, "title": title},
		"roles":    roleLabels(m.defs, g.Roles),
		"from":     map[string]string{"handle": by.Handle, "name": by.Name},
		"grant_id": g.ID,
	})
	return g, err == nil, nil
}

// grantAllowed applies Config.AllowGrant.
func (w *Waka) grantAllowed(ctx context.Context, u *User, res Resource) bool {
	return w.cfg.AllowGrant == nil || w.cfg.AllowGrant(ctx, u, res)
}

// RoleLabel names a role for display.
type RoleLabel struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

func roleLabels(defs []RoleDef, roles []string) []RoleLabel {
	out := []RoleLabel{}
	for _, r := range roles {
		l := RoleLabel{Name: r, Label: r}
		if d := findRole(defs, r); d != nil && d.Label != "" {
			l.Label = d.Label
		}
		out = append(out, l)
	}
	return out
}

// managed loads a grant and checks that by may change or revoke it.
func (w *Waka) managed(ctx context.Context, by *User, grantID string) (*Grant, *manager, error) {
	g, err := w.getGrant(ctx, grantID)
	if err != nil || (g.Kind == KindLink && g.RevokedAt != 0) {
		return nil, nil, ErrNoSuchGrant
	}
	m, err := w.managerFor(ctx, by, g.Resource)
	if err != nil {
		return nil, nil, err
	}
	if err := m.canChange(ctx, g); err != nil {
		return nil, nil, err
	}
	return g, m, nil
}

// ChangeRoles replaces the roles of someone else's grant or of a link, on
// behalf of a user. The rules are those of canChange, and the new roles
// must be ones by may hand out.
func (w *Waka) ChangeRoles(ctx context.Context, by *User, grantID string, roles []string) (*Grant, error) {
	roles = normRoles(roles)
	g, m, err := w.managed(ctx, by, grantID)
	if err != nil {
		return nil, err
	}
	if err := checkAssign(m.mine.perms, m.defs, roles); err != nil {
		return nil, err
	}
	if g.Kind == KindLink && !w.linkAllowed(ctx, g.Resource, g.Public, roles) {
		return nil, ErrForbidden
	}
	return w.SetRoles(ctx, g, roles, by.ID)
}

// RemoveGrant revokes someone else's grant or a link on behalf of a user.
func (w *Waka) RemoveGrant(ctx context.Context, by *User, grantID string) error {
	g, _, err := w.managed(ctx, by, grantID)
	if err != nil {
		return err
	}
	return w.revoke(ctx, GrantRevoked, g, by.ID)
}

// CanChange reports whether a user may change or revoke a grant.
func (w *Waka) CanChange(ctx context.Context, by *User, g *Grant) bool {
	m, err := w.managerFor(ctx, by, g.Resource)
	return err == nil && m.canChange(ctx, g) == nil
}

func (w *Waka) describe(ctx context.Context, res Resource) (string, bool) {
	if w.cfg.Describe == nil {
		return "", false
	}
	return w.cfg.Describe(ctx, res)
}

// --- links ---

// ShareOpener is where Cosmos plugs in. Without one, links are stored here
// and served on this server's own hostname. With one, the link's life
// (secret, password, expiry, hostname, tunnel) belongs to the opener and
// this server keeps only the share ID, the resource and the roles.
type ShareOpener interface {
	// Open creates the share and returns its ID and public URL.
	Open(ctx context.Context, spec ShareSpec) (externalID, url string, err error)
	// Close revokes it.
	Close(ctx context.Context, externalID string) error
	// Verify checks a request the opener forwarded and returns the share it
	// vouches for. The app trusts a share only through this.
	Verify(r *http.Request) (externalID string, ok bool)
}

type ShareSpec struct {
	Resource Resource
	Roles    []string
	// Public: anyone holding the link gets its roles without an account.
	// Otherwise only a Waka account can use it, by claiming it.
	Public    bool
	Password  string
	ExpiresAt int64
	MaxUses   int64
	Label     string
}

// Link is a newly created link. URL is only available at creation.
type Link struct {
	Grant *Grant `json:"grant"`
	URL   string `json:"url"`
}

const linkIDChars = "abcdefghijklmnopqrstuvwxyz0123456789"

// newLinkID is DNS-safe so it can become a share hostname later.
func newLinkID() string {
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = linkIDChars[int(b[i])%len(linkIDChars)]
	}
	return string(b)
}

// CreateLink opens a link on a resource. A public link gives its roles to
// anyone holding it, without signing in; any link can be claimed by a Waka
// account as a grant of its own, which is how an invite works. by must hold
// SharePerm and every permission of the roles, and Config.AllowLink must
// allow them on that kind of link. The owner role is never given by link.
func (w *Waka) CreateLink(ctx context.Context, by *User, spec ShareSpec) (*Link, error) {
	spec.Roles = normRoles(spec.Roles)
	m, err := w.managerFor(ctx, by, spec.Resource)
	if err != nil {
		return nil, err
	}
	if !m.canShare() {
		return nil, ErrForbidden
	}
	if err := checkAssign(m.mine.perms, m.defs, spec.Roles); err != nil {
		return nil, err
	}
	if !w.linkAllowed(ctx, spec.Resource, spec.Public, spec.Roles) {
		return nil, ErrForbidden
	}
	id := newID()
	var linkID, secretHash, passwordHash, externalID, url string
	if w.cfg.Shares != nil {
		if externalID, url, err = w.cfg.Shares.Open(ctx, spec); err != nil {
			return nil, err
		}
	} else {
		secret := newSecret()
		linkID, secretHash = newLinkID(), hashSecret(secret)
		if spec.Password != "" {
			h, err := bcrypt.GenerateFromPassword([]byte(spec.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			passwordHash = string(h)
		}
		// The secret rides in the fragment, which browsers never send.
		url = w.cfg.PublicURL + w.cfg.LinkPath + linkID + "#" + secret
	}
	if _, err := w.db.ExecContext(ctx, w.q(`INSERT INTO waka_grants (id, resource_type, resource_id, kind, roles, status, created_by, created_at, updated_at,
		lookup, secret_hash, password_hash, expires_at, max_uses, external_id, label, public)
		VALUES (?, ?, ?, 'link', ?, 'accepted', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		id, spec.Resource.Type, spec.Resource.ID, encodeRoles(spec.Roles), by.ID, now(), now(),
		linkID, secretHash, passwordHash, spec.ExpiresAt, spec.MaxUses, externalID, spec.Label, spec.Public); err != nil {
		return nil, err
	}
	g, err := w.getGrant(ctx, id)
	if err != nil {
		return nil, err
	}
	w.changed(ctx, GrantCreated, g.Resource, nil, g, by.ID)
	return &Link{Grant: g, URL: url}, nil
}

// findLink validates a locally stored link's secret. A wrong secret counts
// as a try, so a link ID cannot be probed endlessly.
func (w *Waka) findLink(ctx context.Context, linkID, secret string) (*Grant, error) {
	if linkID == "" {
		return nil, ErrLinkDead
	}
	g, err := w.scanGrant(w.db.QueryRowContext(ctx, w.q(`SELECT `+grantCols+` FROM waka_grants WHERE kind = 'link' AND lookup = ?`), linkID))
	if err == nil && g.secretHash != "" && subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(g.secretHash)) == 1 {
		if !g.alive() {
			return nil, ErrLinkDead
		}
		return g, nil
	}
	if !w.attempts.allow("secret:" + linkID) {
		return nil, ErrTooManyTries
	}
	return nil, ErrLinkDead
}

// checkPassword checks a link's password, if it has one. Tries are counted
// per link.
func (w *Waka) checkPassword(g *Grant, password string) error {
	if g.passwordHash == "" {
		return nil
	}
	if !w.attempts.allow("password:" + g.ID) {
		return ErrTooManyTries
	}
	if bcrypt.CompareHashAndPassword([]byte(g.passwordHash), []byte(password)) != nil {
		return ErrBadPassword
	}
	return nil
}

// checkLink validates a link's secret and password.
func (w *Waka) checkLink(ctx context.Context, linkID, secret, password string) (*Grant, error) {
	g, err := w.findLink(ctx, linkID, secret)
	if err != nil {
		return nil, err
	}
	if err := w.checkPassword(g, password); err != nil {
		return nil, err
	}
	return g, nil
}

// Persona is how someone appears on this server, for other people.
type Persona struct {
	Handle  string `json:"handle"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// LinkPreview is the card a client shows before joining through a link.
type LinkPreview struct {
	Server   map[string]string `json:"server"`
	Resource struct {
		Type  string `json:"type"`
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"resource"`
	Roles []RoleLabel `json:"roles"`
	// InvitedBy is who made the link, as they appear on this server.
	InvitedBy   *Persona `json:"invited_by"`
	Public      bool     `json:"public"`
	HasPassword bool     `json:"has_password"`
	// Locked: the link has a password and it was not given, so the title
	// and who made it are left out.
	Locked    bool  `json:"locked"`
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// PreviewLink reads what a link leads to, without a session. With a
// password set on the link, the title and the person who made it are only
// shown with the right password; wrong ones count as tries.
func (w *Waka) PreviewLink(ctx context.Context, linkID, secret, password string) (*LinkPreview, error) {
	g, err := w.findLink(ctx, linkID, secret)
	if err != nil {
		return nil, err
	}
	locked := false
	if g.HasPassword {
		if password == "" {
			locked = true
		} else if err := w.checkPassword(g, password); err != nil {
			return nil, err
		}
	}
	defs, err := w.RolesFor(ctx, g.Resource)
	if err != nil {
		return nil, err
	}
	p := &LinkPreview{Server: w.serverInfo(), Roles: roleLabels(defs, g.Roles), Public: g.Public,
		HasPassword: g.HasPassword, Locked: locked, ExpiresAt: g.ExpiresAt}
	p.Resource.Type, p.Resource.ID = g.Resource.Type, g.Resource.ID
	if !locked {
		p.Resource.Title, _ = w.describe(ctx, g.Resource)
		if u, err := w.GetUser(ctx, g.CreatedBy); err == nil {
			p.InvitedBy = w.persona(u)
		}
	}
	return p, nil
}

func (w *Waka) persona(u *User) *Persona {
	p := &Persona{Handle: u.Handle, Name: u.Name}
	if u.Avatar != "" {
		p.Picture = w.address() + u.Avatar
	}
	return p
}

// RedeemLink exchanges a public link for an anonymous session limited to it.
// A link for accounts gives no session; it can only be claimed.
func (w *Waka) RedeemLink(ctx context.Context, linkID, secret, password string) (*Session, *Grant, error) {
	g, err := w.checkLink(ctx, linkID, secret, password)
	if err != nil {
		return nil, nil, err
	}
	if !g.Public {
		return nil, nil, ErrAccountsOnly
	}
	ttl := 24 * time.Hour
	if g.ExpiresAt != 0 {
		ttl = min(ttl, time.Until(time.Unix(g.ExpiresAt, 0)))
	}
	s, err := w.signSession(sessionClaims{Type: "link", GrantID: g.ID}, ttl)
	return s, g, err
}

// ClaimLink turns a link into the signed-in user's own accepted grant ("add
// to my account"), adding its roles to any the user holds. MaxUses counts
// claims that changed something.
func (w *Waka) ClaimLink(ctx context.Context, u *User, linkID, secret, password string) (*Grant, error) {
	link, err := w.checkLink(ctx, linkID, secret, password)
	if err != nil {
		return nil, err
	}
	return w.claim(ctx, u, link)
}

func (w *Waka) claim(ctx context.Context, u *User, link *Grant) (*Grant, error) {
	if !w.grantAllowed(ctx, u, link.Resource) {
		return nil, ErrForbidden
	}
	if existing, err := w.userGrant(ctx, link.Resource, u.ID); err == nil && existing.Status == StatusAccepted &&
		!slices.ContainsFunc(link.Roles, func(r string) bool { return !slices.Contains(existing.Roles, r) }) {
		return existing, nil
	}
	// Counting first means two claims cannot both take the last use.
	res, err := w.db.ExecContext(ctx, w.q(`UPDATE waka_grants SET uses = uses + 1 WHERE id = ? AND revoked_at = 0 AND (max_uses = 0 OR uses < max_uses)`), link.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrLinkDead
	}
	before, after, err := w.addRoles(ctx, link.Resource, u.ID, link.Roles, StatusAccepted, link.CreatedBy)
	if err != nil {
		return nil, err
	}
	w.changed(ctx, GrantClaimed, link.Resource, before, after, u.ID)
	return after, nil
}

// JoinLink claims a link with a token the hub made out to this server, and
// signs the user in. It is how someone joins from a link with nothing but
// their hub login, so it works where SignInInvite would turn them away.
func (w *Waka) JoinLink(ctx context.Context, hubToken, linkID, secret, password string) (*Session, *Grant, error) {
	link, err := w.checkLink(ctx, linkID, secret, password)
	if err != nil {
		return nil, nil, err
	}
	s, err := w.login(ctx, hubToken, true)
	if err != nil {
		return nil, nil, err
	}
	g, err := w.claim(ctx, s.User, link)
	if err != nil {
		return nil, nil, err
	}
	return s, g, nil
}

// attempts throttles guesses per link.
type attempts struct {
	mu sync.Mutex
	m  map[string]*attemptWindow
}

type attemptWindow struct {
	count int
	reset time.Time
}

func newAttempts() *attempts { return &attempts{m: map[string]*attemptWindow{}} }

// allow counts a try and reports whether it is within 10 a minute.
func (a *attempts) allow(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := time.Now()
	if len(a.m) > 10000 {
		for k, w := range a.m {
			if t.After(w.reset) {
				delete(a.m, k)
			}
		}
	}
	w := a.m[key]
	if w == nil || t.After(w.reset) {
		w = &attemptWindow{reset: t.Add(time.Minute)}
		a.m[key] = w
	}
	w.count++
	return w.count <= 10
}
