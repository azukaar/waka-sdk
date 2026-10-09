package waka

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Handler serves the routes every app shares. Mount it at "/waka/" and at
// "/.well-known/waka-server".
func (w *Waka) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /.well-known/waka-server", w.handleInfo)

	m.HandleFunc("POST /waka/session", w.handleSession)
	m.HandleFunc("GET /waka/login", w.handleWebLogin)
	m.HandleFunc("GET /waka/callback", w.handleWebCallback)
	m.HandleFunc("POST /waka/logout", w.handleLogout)
	m.HandleFunc("GET /waka/me", w.RequireUser(w.handleMe))
	m.HandleFunc("GET /waka/users/{id}/avatar", w.handleAvatar)

	m.HandleFunc("GET /waka/joined", w.RequireUser(w.handleJoined))
	m.HandleFunc("GET /waka/invites", w.RequireUser(w.handleInvites))
	m.HandleFunc("GET /waka/joinable", w.RequireUser(w.handleJoinable))
	m.HandleFunc("POST /waka/join", w.RequireUser(w.handleJoin))

	m.HandleFunc("GET /waka/roles", w.RequireUser(w.handleRoles))
	m.HandleFunc("GET /waka/grants", w.RequireUser(w.handleListGrants))
	m.HandleFunc("POST /waka/grants", w.RequireUser(w.handleShare))
	m.HandleFunc("PATCH /waka/grants/{id}", w.RequireUser(w.handleUpdateGrant))
	m.HandleFunc("DELETE /waka/grants/{id}", w.RequireUser(w.handleRevokeGrant))
	m.HandleFunc("POST /waka/grants/{id}/{action}", w.RequireUser(w.handleGrantAction))

	m.HandleFunc("POST /waka/links", w.RequireUser(w.handleCreateLink))
	m.HandleFunc("POST /waka/links/preview", w.handlePreviewLink)
	m.HandleFunc("POST /waka/links/redeem", w.handleRedeemLink)
	m.HandleFunc("POST /waka/links/claim", w.RequireUser(w.handleClaimLink))
	m.HandleFunc("POST /waka/links/join", w.handleJoinLink)

	m.HandleFunc("GET /waka/bans", w.RequireUser(w.handleListBans))
	m.HandleFunc("POST /waka/bans", w.RequireUser(w.handleBan))
	m.HandleFunc("DELETE /waka/bans/{id}", w.RequireUser(w.handleUnban))
	return m
}

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(v)
}

func writeErr(rw http.ResponseWriter, status int, msg string) {
	writeJSON(rw, status, map[string]string{"error": msg})
}

func readJSON(rw http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(rw, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(rw, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// fail maps the library's errors onto HTTP statuses.
func fail(rw http.ResponseWriter, err error) {
	var he *HubError
	switch {
	case errors.Is(err, ErrForbidden):
		writeErr(rw, http.StatusForbidden, "not allowed")
	case errors.Is(err, ErrBanned), errors.Is(err, ErrNotAllowed), errors.Is(err, ErrAccountsOnly):
		writeErr(rw, http.StatusForbidden, strings.TrimPrefix(err.Error(), "waka: "))
	case errors.Is(err, ErrNoSuchGrant), errors.Is(err, ErrUserNotFound), errors.Is(err, ErrLinkDead):
		writeErr(rw, http.StatusNotFound, strings.TrimPrefix(err.Error(), "waka: "))
	case errors.Is(err, ErrBadRole):
		writeErr(rw, http.StatusBadRequest, "unknown role")
	case errors.Is(err, ErrNotApplicable):
		writeErr(rw, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "waka: "))
	case errors.Is(err, ErrBadPassword):
		writeErr(rw, http.StatusUnauthorized, "wrong password")
	case errors.Is(err, ErrTooManyTries):
		writeErr(rw, http.StatusTooManyRequests, strings.TrimPrefix(err.Error(), "waka: "))
	case errors.As(err, &he):
		status := http.StatusBadGateway
		if he.Status == http.StatusTooManyRequests {
			status = he.Status
		}
		writeErr(rw, status, he.Message)
	default:
		log.Printf("waka: %v", err)
		writeErr(rw, http.StatusInternalServerError, "internal error")
	}
}

func (w *Waka) handleInfo(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, http.StatusOK, map[string]any{
		"server_id": w.cfg.ServerID, "issuer": w.cfg.Issuer, "name": w.cfg.Name, "app": w.cfg.App, "sign_in": w.SignInMode(),
	})
}

// --- sessions ---

func (w *Waka) handleSession(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !readJSON(rw, r, &req) {
		return
	}
	s, err := w.Login(r.Context(), req.Token)
	switch {
	case errors.Is(err, ErrBanned), errors.Is(err, ErrNotAllowed):
		fail(rw, err)
	case err != nil:
		writeErr(rw, http.StatusUnauthorized, "invalid hub token")
	default:
		writeJSON(rw, http.StatusOK, s)
	}
}

const loginCookie = "waka_login"

func (w *Waka) secure() bool { return strings.HasPrefix(w.cfg.PublicURL, "https://") }

// handleWebLogin starts the login of a web page served by this server: one
// redirect to the hub and back, with no prompt while the user is signed in
// there. The page ends up with a session cookie for this server only.
func (w *Waka) handleWebLogin(rw http.ResponseWriter, r *http.Request) {
	ret := r.URL.Query().Get("return")
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") {
		ret = "/"
	}
	state, verifier := newSecret(), newSecret()
	sum := sha256.Sum256([]byte(verifier))
	http.SetCookie(rw, &http.Cookie{
		Name: loginCookie, Value: state + "." + verifier + "." + url.QueryEscape(ret),
		Path: "/waka/", MaxAge: 600, HttpOnly: true, Secure: w.secure(), SameSite: http.SameSiteLaxMode,
	})
	q := url.Values{
		"mode":           {"server"},
		"server_id":      {w.cfg.ServerID},
		"redirect_uri":   {w.cfg.PublicURL + "/waka/callback"},
		"state":          {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
	}
	if p := r.URL.Query().Get("prompt"); p != "" {
		q.Set("prompt", p)
	}
	http.Redirect(rw, r, w.cfg.Issuer+"/auth/start?"+q.Encode(), http.StatusFound)
}

func (w *Waka) handleWebCallback(rw http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(loginCookie)
	if err != nil {
		http.Error(rw, "login expired, please start again", http.StatusBadRequest)
		return
	}
	http.SetCookie(rw, &http.Cookie{Name: loginCookie, Path: "/waka/", MaxAge: -1})
	parts := strings.SplitN(c.Value, ".", 3)
	if len(parts) != 3 || parts[0] != r.URL.Query().Get("state") {
		http.Error(rw, "login state mismatch", http.StatusBadRequest)
		return
	}
	ret, _ := url.QueryUnescape(parts[2])
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(rw, "login was not completed: "+e, http.StatusForbidden)
		return
	}
	token, err := w.redeemAtHub(r.Context(), r.URL.Query().Get("code"), parts[1])
	if err != nil {
		http.Error(rw, "login failed at the hub", http.StatusBadGateway)
		return
	}
	s, err := w.Login(r.Context(), token)
	if err != nil {
		http.Error(rw, strings.TrimPrefix(err.Error(), "waka: "), http.StatusForbidden)
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: s.Token, Path: "/", MaxAge: int(w.cfg.SessionTTL.Seconds()),
		HttpOnly: true, Secure: w.secure(), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(rw, r, ret, http.StatusSeeOther)
}

func (w *Waka) redeemAtHub(ctx context.Context, code, verifier string) (string, error) {
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Issuer+"/auth/redeem", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil || out.Token == "" {
		return "", errors.New("waka: hub refused the code")
	}
	return out.Token, nil
}

func (w *Waka) handleLogout(rw http.ResponseWriter, r *http.Request) {
	http.SetCookie(rw, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
	rw.WriteHeader(http.StatusNoContent)
}

func (w *Waka) handleMe(rw http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(rw, http.StatusOK, map[string]any{"user": u, "admin": w.IsAdmin(u), "owner": w.IsOwner(u)})
}

func (w *Waka) handleAvatar(rw http.ResponseWriter, r *http.Request) {
	var data []byte
	var ctype string
	err := w.db.QueryRowContext(r.Context(), w.q(`SELECT avatar, avatar_type FROM waka_users WHERE id = ? AND avatar IS NOT NULL`),
		r.PathValue("id")).Scan(&data, &ctype)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", ctype)
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Write(data)
}

// --- what have I joined, what could I join ---

type grantView struct {
	*Grant
	Title string `json:"title,omitempty"`
	User  *User  `json:"user,omitempty"`
	By    *User  `json:"invited_by,omitempty"`
	// Editable: the caller may change or revoke it. Only in GET /waka/grants.
	Editable bool `json:"editable,omitempty"`
}

func (w *Waka) view(ctx context.Context, grants []*Grant, withUsers bool) []grantView {
	out := make([]grantView, 0, len(grants))
	for _, g := range grants {
		v := grantView{Grant: g}
		v.Title, _ = w.describe(ctx, g.Resource)
		if withUsers {
			if g.UserID != "" {
				v.User, _ = w.GetUser(ctx, g.UserID)
			}
			if g.CreatedBy != "" && g.CreatedBy != g.UserID {
				v.By, _ = w.GetUser(ctx, g.CreatedBy)
			}
		}
		out = append(out, v)
	}
	return out
}

func (w *Waka) handleJoined(rw http.ResponseWriter, r *http.Request, u *User) {
	grants, err := w.Joined(r.Context(), u.ID)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, w.view(r.Context(), grants, false))
}

func (w *Waka) handleInvites(rw http.ResponseWriter, r *http.Request, u *User) {
	grants, err := w.Invites(r.Context(), u.ID)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, w.view(r.Context(), grants, true))
}

func (w *Waka) handleJoinable(rw http.ResponseWriter, r *http.Request, u *User) {
	items := []Joinable{}
	if w.cfg.Joinable != nil {
		var err error
		if items, err = w.cfg.Joinable(r.Context(), u); err != nil {
			fail(rw, err)
			return
		}
	}
	writeJSON(rw, http.StatusOK, items)
}

func (w *Waka) handleJoin(rw http.ResponseWriter, r *http.Request, u *User) {
	var res Resource
	if !readJSON(rw, r, &res) {
		return
	}
	g, err := w.Join(r.Context(), u, res)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, g)
}

// handleGrantAction is how a user answers an invite or leaves. These are
// always writes to the server, never a choice kept on the client.
func (w *Waka) handleGrantAction(rw http.ResponseWriter, r *http.Request, u *User) {
	ctx, id := r.Context(), r.PathValue("id")
	var err error
	switch r.PathValue("action") {
	case "accept":
		_, err = w.Accept(ctx, u, id)
	case "decline":
		err = w.Decline(ctx, u, id)
	case "leave":
		err = w.Leave(ctx, u, id)
	default:
		err = ErrNotApplicable
	}
	if err != nil {
		fail(rw, err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// --- managing who has access ---

func resourceQuery(r *http.Request) Resource {
	return Resource{Type: r.URL.Query().Get("type"), ID: r.URL.Query().Get("id")}
}

func (w *Waka) handleRoles(rw http.ResponseWriter, r *http.Request, u *User) {
	info, err := w.RoleInfo(r.Context(), u, resourceQuery(r))
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, info)
}

// handleListGrants lists who has access, for someone who may share: every
// user grant, and the links they made. Someone who may manage sees every
// link. Each grant says whether the caller may change it.
func (w *Waka) handleListGrants(rw http.ResponseWriter, r *http.Request, u *User) {
	ctx, res := r.Context(), resourceQuery(r)
	m, err := w.managerFor(ctx, u, res)
	if err != nil {
		fail(rw, err)
		return
	}
	if !m.canShare() {
		fail(rw, ErrForbidden)
		return
	}
	grants, err := w.GrantsOn(ctx, res)
	if err != nil {
		fail(rw, err)
		return
	}
	shown := []*Grant{}
	for _, g := range grants {
		if g.Kind == KindUser || g.CreatedBy == u.ID || m.canManage() {
			shown = append(shown, g)
		}
	}
	views := w.view(ctx, shown, true)
	for i := range views {
		views[i].Editable = m.canChange(ctx, views[i].Grant) == nil
	}
	writeJSON(rw, http.StatusOK, views)
}

func (w *Waka) handleShare(rw http.ResponseWriter, r *http.Request, u *User) {
	var req struct {
		Resource Resource `json:"resource"`
		Target   string   `json:"target"`
		Roles    []string `json:"roles"`
	}
	if !readJSON(rw, r, &req) {
		return
	}
	g, delivered, err := w.Share(r.Context(), u, req.Resource, req.Target, req.Roles)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"grant": g, "delivered": delivered})
}

func (w *Waka) handleUpdateGrant(rw http.ResponseWriter, r *http.Request, u *User) {
	var req struct {
		Roles []string `json:"roles"`
	}
	if !readJSON(rw, r, &req) {
		return
	}
	g, err := w.ChangeRoles(r.Context(), u, r.PathValue("id"), req.Roles)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, g)
}

func (w *Waka) handleRevokeGrant(rw http.ResponseWriter, r *http.Request, u *User) {
	if err := w.RemoveGrant(r.Context(), u, r.PathValue("id")); err != nil {
		fail(rw, err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// --- links ---

func (w *Waka) handleCreateLink(rw http.ResponseWriter, r *http.Request, u *User) {
	var req struct {
		Resource  Resource `json:"resource"`
		Roles     []string `json:"roles"`
		Public    bool     `json:"public"`
		Password  string   `json:"password"`
		ExpiresAt int64    `json:"expires_at"`
		MaxUses   int64    `json:"max_uses"`
		Label     string   `json:"label"`
	}
	if !readJSON(rw, r, &req) {
		return
	}
	if req.MaxUses < 0 || len(req.Label) > 100 || (req.ExpiresAt != 0 && req.ExpiresAt <= now()) {
		writeErr(rw, http.StatusBadRequest, "invalid link options")
		return
	}
	link, err := w.CreateLink(r.Context(), u, ShareSpec{
		Resource: req.Resource, Roles: req.Roles, Public: req.Public, Password: req.Password,
		ExpiresAt: req.ExpiresAt, MaxUses: req.MaxUses, Label: req.Label,
	})
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusCreated, link)
}

type linkRequest struct {
	ID       string `json:"id"`
	Secret   string `json:"secret"`
	Password string `json:"password"`
}

// failLink is fail, except that a missing password is told apart from a
// wrong one, so a landing page asks for it only when one is set.
func failLink(rw http.ResponseWriter, err error, password string) {
	if errors.Is(err, ErrBadPassword) && password == "" {
		writeErr(rw, http.StatusUnauthorized, "password required")
		return
	}
	fail(rw, err)
}

func (w *Waka) handlePreviewLink(rw http.ResponseWriter, r *http.Request) {
	var req linkRequest
	if !readJSON(rw, r, &req) {
		return
	}
	p, err := w.PreviewLink(r.Context(), req.ID, req.Secret, req.Password)
	if err != nil {
		failLink(rw, err, req.Password)
		return
	}
	writeJSON(rw, http.StatusOK, p)
}

func (w *Waka) handleRedeemLink(rw http.ResponseWriter, r *http.Request) {
	var req linkRequest
	if !readJSON(rw, r, &req) {
		return
	}
	s, g, err := w.RedeemLink(r.Context(), req.ID, req.Secret, req.Password)
	if err != nil {
		failLink(rw, err, req.Password)
		return
	}
	title, _ := w.describe(r.Context(), g.Resource)
	writeJSON(rw, http.StatusOK, map[string]any{
		"session": s.Token, "expires_at": s.ExpiresAt, "resource": g.Resource, "roles": g.Roles, "title": title,
	})
}

func (w *Waka) handleClaimLink(rw http.ResponseWriter, r *http.Request, u *User) {
	var req linkRequest
	if !readJSON(rw, r, &req) {
		return
	}
	g, err := w.ClaimLink(r.Context(), u, req.ID, req.Secret, req.Password)
	if err != nil {
		failLink(rw, err, req.Password)
		return
	}
	writeJSON(rw, http.StatusOK, g)
}

// handleJoinLink claims a link with a hub token instead of a session: the
// way in for someone this server has not let in yet.
func (w *Waka) handleJoinLink(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		linkRequest
		Token string `json:"token"`
	}
	if !readJSON(rw, r, &req) {
		return
	}
	s, g, err := w.JoinLink(r.Context(), req.Token, req.ID, req.Secret, req.Password)
	var he *HubError
	switch {
	case err == nil:
		writeJSON(rw, http.StatusOK, map[string]any{"session": s.Token, "expires_at": s.ExpiresAt, "user": s.User, "grant": g})
	case errors.Is(err, ErrBanned), errors.Is(err, ErrNotAllowed), errors.Is(err, ErrLinkDead), errors.Is(err, ErrBadPassword),
		errors.Is(err, ErrTooManyTries), errors.Is(err, ErrForbidden), errors.As(err, &he):
		failLink(rw, err, req.Password)
	default:
		writeErr(rw, http.StatusUnauthorized, "invalid hub token")
	}
}

// --- bans ---

func (w *Waka) admin(rw http.ResponseWriter, u *User) bool {
	if !w.IsAdmin(u) {
		fail(rw, ErrForbidden)
		return false
	}
	return true
}

func (w *Waka) handleListBans(rw http.ResponseWriter, r *http.Request, u *User) {
	if !w.admin(rw, u) {
		return
	}
	rows, err := w.db.QueryContext(r.Context(), w.q(`SELECT u.id, u.handle, u.name, b.issuer, b.reason, b.created_at
		FROM waka_bans b JOIN waka_users u ON u.issuer = b.issuer AND u.subject = b.subject ORDER BY b.created_at`))
	if err != nil {
		fail(rw, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, handle, name, issuer, reason string
		var created int64
		if err := rows.Scan(&id, &handle, &name, &issuer, &reason, &created); err != nil {
			fail(rw, err)
			return
		}
		out = append(out, map[string]any{"user_id": id, "handle": handle, "name": name, "issuer": issuer, "reason": reason, "created_at": created})
	}
	writeJSON(rw, http.StatusOK, out)
}

// handleBan bans by local user ID, or by handle for someone this server has
// not seen yet.
func (w *Waka) handleBan(rw http.ResponseWriter, r *http.Request, u *User) {
	if !w.admin(rw, u) {
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Handle string `json:"handle"`
		Reason string `json:"reason"`
	}
	if !readJSON(rw, r, &req) {
		return
	}
	ctx := r.Context()
	var target *User
	var err error
	if req.UserID != "" {
		target, err = w.GetUser(ctx, req.UserID)
	} else {
		var hu *HubUser
		if hu, err = w.LookupUser(ctx, req.Handle); err == nil {
			target, err = w.ensureUser(ctx, w.cfg.Issuer, hu.ID, hu.Handle, hu.Name)
		}
	}
	if err != nil {
		fail(rw, err)
		return
	}
	if w.IsAdmin(target) {
		fail(rw, ErrForbidden)
		return
	}
	if err := w.Ban(ctx, target, req.Reason); err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"user": target})
}

func (w *Waka) handleUnban(rw http.ResponseWriter, r *http.Request, u *User) {
	if !w.admin(rw, u) {
		return
	}
	target, err := w.GetUser(r.Context(), r.PathValue("id"))
	if err == nil {
		err = w.Unban(r.Context(), target)
	}
	if err != nil {
		fail(rw, err)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}
