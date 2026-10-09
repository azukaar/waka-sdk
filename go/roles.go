package waka

import (
	"context"
	"errors"
	"log"
	"slices"
	"sort"
)

// Roles belong to the app. A resource offers roles, each carrying
// permissions, and the app may change that list at any time; the library
// asks for it every time it needs it. All the library stores is which role
// names each grant holds. Permissions are the app's own strings.

// RoleDef is one role a resource offers. Name is what grants store, so it
// must stay stable: use an ID if people can rename roles. At most one role
// per resource is the owner role, which is never handed out by sharing, by
// link or by a role change; only the app's own Grant and SetRoles give it.
type RoleDef struct {
	Name  string   `json:"name"`
	Label string   `json:"label"`
	Perms []string `json:"perms"`
	Owner bool     `json:"owner,omitempty"`
}

// DefaultRoles is the ladder used when Config.Roles is nil. Each role
// carries the permissions of the ones below it.
var DefaultRoles = []RoleDef{
	{Name: "read", Label: "Can view", Perms: []string{"read"}},
	{Name: "edit", Label: "Can edit", Perms: []string{"read", "edit"}},
	{Name: "admin", Label: "Can share", Perms: []string{"read", "edit", "share", "manage"}},
	{Name: "owner", Label: "Owner", Perms: []string{"read", "edit", "share", "manage", "delete"}, Owner: true},
}

// RolesFor returns the roles a resource offers.
func (w *Waka) RolesFor(ctx context.Context, res Resource) ([]RoleDef, error) {
	if w.cfg.Roles == nil {
		return DefaultRoles, nil
	}
	defs, err := w.cfg.Roles(ctx, res)
	if err != nil {
		return nil, err
	}
	owners, seen := 0, map[string]bool{}
	for _, d := range defs {
		if d.Name == "" || seen[d.Name] {
			return nil, errors.New("waka: a role has no name or the same name as another")
		}
		seen[d.Name] = true
		if d.Owner {
			owners++
		}
	}
	if owners > 1 {
		return nil, errors.New("waka: more than one owner role")
	}
	return defs, nil
}

func findRole(defs []RoleDef, name string) *RoleDef {
	for i := range defs {
		if defs[i].Name == name {
			return &defs[i]
		}
	}
	return nil
}

// holdsOwner reports whether a set of role names includes the owner role.
func holdsOwner(defs []RoleDef, roles []string) bool {
	for _, r := range roles {
		if d := findRole(defs, r); d != nil && d.Owner {
			return true
		}
	}
	return false
}

// normRoles sorts and dedupes a set of role names.
func normRoles(roles []string) []string {
	out := []string{}
	for _, r := range roles {
		if r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

func unionRoles(a, b []string) []string { return normRoles(append(slices.Clone(a), b...)) }

// perms is a set of permissions. all stands for every permission there is,
// which is what AdminPower gives.
type perms struct {
	set map[string]bool
	all bool
}

func (p *perms) has(perm string) bool { return p.all || p.set[perm] }

func (p *perms) add(defs []RoleDef, roles []string) {
	for _, r := range roles {
		if d := findRole(defs, r); d != nil {
			for _, perm := range d.Perms {
				p.set[perm] = true
			}
		}
	}
}

// covers reports whether p holds everything o holds.
func (p *perms) covers(o *perms) bool {
	if p.all {
		return true
	}
	if o.all {
		return false
	}
	for perm := range o.set {
		if !p.set[perm] {
			return false
		}
	}
	return true
}

func (p *perms) list() []string {
	out := make([]string, 0, len(p.set))
	for perm := range p.set {
		out = append(out, perm)
	}
	sort.Strings(out)
	return out
}

func rolePerms(defs []RoleDef, roles []string) *perms {
	p := &perms{set: map[string]bool{}}
	p.add(defs, roles)
	return p
}

// access is what a principal holds on a resource: the roles held on it
// directly, and the permissions those and every inherited role carry.
type access struct {
	roles []string
	perms *perms
}

// access resolves a principal's roles on a resource and up through its
// parents, and unions the permissions they carry there.
func (w *Waka) access(ctx context.Context, p *Principal, res Resource) (*access, error) {
	a := &access{roles: []string{}, perms: &perms{set: map[string]bool{}}}
	if p == nil {
		return a, nil
	}
	if p.User != nil && w.cfg.AdminPower && w.IsAdmin(p.User) {
		a.perms.all = true
	}
	cur := res
	for depth := 0; depth < 16; depth++ {
		roles := w.heldRoles(ctx, p, cur)
		if depth == 0 {
			a.roles = roles
		}
		if len(roles) > 0 {
			defs, err := w.RolesFor(ctx, cur)
			if err != nil {
				return nil, err
			}
			a.perms.add(defs, roles)
		}
		if w.cfg.Parent == nil {
			break
		}
		parent, ok := w.cfg.Parent(ctx, cur)
		if !ok {
			break
		}
		cur = parent
	}
	if a.perms.all {
		// Spelled out too, so Perms lists what the resource's roles carry.
		if defs, err := w.RolesFor(ctx, res); err == nil {
			for _, d := range defs {
				a.perms.add(defs, []string{d.Name})
			}
		}
		a.perms.set[w.cfg.SharePerm], a.perms.set[w.cfg.ManagePerm] = true, true
	}
	return a, nil
}

// heldRoles are the roles a principal holds on one resource itself.
func (w *Waka) heldRoles(ctx context.Context, p *Principal, res Resource) []string {
	switch {
	case p.User != nil:
		var raw string
		if w.db.QueryRowContext(ctx, w.q(`SELECT roles FROM waka_grants WHERE kind = 'user' AND user_id = ?
			AND resource_type = ? AND resource_id = ? AND status = 'accepted'`), p.User.ID, res.Type, res.ID).Scan(&raw) == nil {
			return decodeRoles(raw)
		}
	case p.Link != nil && p.Link.Resource == res && p.Link.alive():
		return p.Link.Roles
	}
	return []string{}
}

func (w *Waka) accessOrNone(ctx context.Context, p *Principal, res Resource) *access {
	a, err := w.access(ctx, p, res)
	if err != nil {
		log.Printf("waka: roles of %s %s: %v", res.Type, res.ID, err)
		return &access{roles: []string{}, perms: &perms{set: map[string]bool{}}}
	}
	return a
}

// Has is the permission check: whether a principal holds a permission on a
// resource, through its own roles there, roles inherited through Parent, or
// AdminPower. A failing Roles hook counts as no permission.
func (w *Waka) Has(ctx context.Context, p *Principal, res Resource, perm string) bool {
	return w.accessOrNone(ctx, p, res).perms.has(perm)
}

// Perms lists the permissions a principal holds on a resource.
func (w *Waka) Perms(ctx context.Context, p *Principal, res Resource) []string {
	return w.accessOrNone(ctx, p, res).perms.list()
}

// RolesOf lists the roles a principal holds on a resource itself, not
// counting inherited ones.
func (w *Waka) RolesOf(ctx context.Context, p *Principal, res Resource) []string {
	return w.accessOrNone(ctx, p, res).roles
}

// checkAssign checks that someone holding mine may hand out these roles:
// each must exist, must not be the owner role, and must carry nothing they
// do not hold themselves.
func checkAssign(mine *perms, defs []RoleDef, roles []string) error {
	if len(roles) == 0 {
		return ErrBadRole
	}
	for _, r := range roles {
		d := findRole(defs, r)
		if d == nil {
			return ErrBadRole
		}
		if d.Owner {
			return ErrForbidden
		}
		for _, perm := range d.Perms {
			if !mine.has(perm) {
				return ErrForbidden
			}
		}
	}
	return nil
}

// manager is what one user may do with the grants of one resource. Built
// once per request, it answers for each grant.
type manager struct {
	w    *Waka
	by   *User
	res  Resource
	defs []RoleDef
	mine *access
}

func (w *Waka) managerFor(ctx context.Context, by *User, res Resource) (*manager, error) {
	defs, err := w.RolesFor(ctx, res)
	if err != nil {
		return nil, err
	}
	mine, err := w.access(ctx, &Principal{User: by}, res)
	if err != nil {
		return nil, err
	}
	return &manager{w: w, by: by, res: res, defs: defs, mine: mine}, nil
}

func (m *manager) canShare() bool  { return m.mine.perms.has(m.w.cfg.SharePerm) }
func (m *manager) canManage() bool { return m.mine.perms.has(m.w.cfg.ManagePerm) }

// canChange checks that the user may change or revoke a grant: they can
// share, the grant is their own link or pending invite or they can manage,
// the grant is not the owner's, and whoever holds it holds nothing the user
// does not. Nobody changes their own grant this way; they leave.
func (m *manager) canChange(ctx context.Context, g *Grant) error {
	if g.Kind == KindUser && g.UserID == m.by.ID {
		return ErrForbidden
	}
	if holdsOwner(m.defs, g.Roles) || !m.canShare() {
		return ErrForbidden
	}
	own := g.CreatedBy == m.by.ID && (g.Kind == KindLink || g.Status == StatusPending)
	if !own && !m.canManage() {
		return ErrForbidden
	}
	theirs := rolePerms(m.defs, g.Roles)
	if g.Kind == KindUser {
		if u, err := m.w.GetUser(ctx, g.UserID); err == nil {
			a, err := m.w.access(ctx, &Principal{User: u}, g.Resource)
			if err != nil {
				return err
			}
			theirs.all = a.perms.all
			for perm := range a.perms.set {
				theirs.set[perm] = true
			}
		}
	}
	if !m.mine.perms.covers(theirs) {
		return ErrForbidden
	}
	return nil
}

// linkAllowed applies Config.AllowLink.
func (w *Waka) linkAllowed(ctx context.Context, res Resource, public bool, roles []string) bool {
	return w.cfg.AllowLink == nil || w.cfg.AllowLink(ctx, res, public, roles)
}

// RoleView is one of a resource's roles as one user sees it.
type RoleView struct {
	RoleDef
	// Assignable: the user may hand this role out by sharing or a role change.
	Assignable bool `json:"assignable"`
	// Link and PublicLink: it may also be put on a link for accounts, or on
	// a public link.
	Link       bool `json:"link"`
	PublicLink bool `json:"public_link"`
}

// RoleInfo is what a share dialog needs about a resource: its roles, which
// of them the user may hand out, and what the user holds.
type RoleInfo struct {
	Resource Resource   `json:"resource"`
	Roles    []RoleView `json:"roles"`
	Mine     struct {
		Roles []string `json:"roles"`
		Perms []string `json:"perms"`
	} `json:"mine"`
	CanShare  bool `json:"can_share"`
	CanManage bool `json:"can_manage"`
}

// RoleInfo describes a resource's roles for a user who holds anything on it.
func (w *Waka) RoleInfo(ctx context.Context, u *User, res Resource) (*RoleInfo, error) {
	m, err := w.managerFor(ctx, u, res)
	if err != nil {
		return nil, err
	}
	if !m.mine.perms.all && len(m.mine.perms.set) == 0 {
		return nil, ErrForbidden
	}
	info := &RoleInfo{Resource: res, Roles: []RoleView{}, CanShare: m.canShare(), CanManage: m.canManage()}
	info.Mine.Roles, info.Mine.Perms = m.mine.roles, m.mine.perms.list()
	for _, d := range m.defs {
		v := RoleView{RoleDef: d}
		v.Assignable = info.CanShare && checkAssign(m.mine.perms, m.defs, []string{d.Name}) == nil
		v.Link = v.Assignable && w.linkAllowed(ctx, res, false, []string{d.Name})
		v.PublicLink = v.Assignable && w.linkAllowed(ctx, res, true, []string{d.Name})
		info.Roles = append(info.Roles, v)
	}
	return info, nil
}
