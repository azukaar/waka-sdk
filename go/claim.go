package waka

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Unclaimed is what a server serves before anyone owns it: it has a hub but no
// credentials yet. It starts like any other server, and the first person to
// add it claims it. Their client registers the server on the hub under their
// own account (which makes them its owner) and hands the credentials over to
// POST /waka/claim; the server checks them with the hub and keeps them.
//
// There is no setup step on the server and no secret to copy: whoever gets
// there first owns it, as with most self-hosted software. A server claimed by
// the wrong person is reset by deleting its stored credentials.
type Unclaimed struct {
	// Issuer is the hub the server will belong to.
	Issuer string
	// App is the server's app; the hub refuses credentials of another app.
	App string
	// Name is what the hub lists the server as until it says otherwise.
	Name string
	// PublicURL is the address the hub records for it.
	PublicURL string
	// OnClaim keeps the credentials and brings the server up with them. It
	// runs once, after the hub accepted them; an error leaves it unclaimed.
	OnClaim func(ctx context.Context, serverID, secret string) error
	// HTTPClient talks to the hub. Default: 10s timeout.
	HTTPClient *http.Client

	mu      sync.Mutex
	claimed bool
}

// Handler serves "/.well-known/waka-server", saying it can be claimed, and
// "POST /waka/claim". Everything else is 503 until the server is claimed.
func (u *Unclaimed) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /.well-known/waka-server", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, http.StatusOK, map[string]any{
			"issuer": strings.TrimRight(u.Issuer, "/"), "app": u.App, "name": u.Name, "claimed": false,
		})
	})
	m.HandleFunc("POST /waka/claim", u.handleClaim)
	m.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		writeErr(rw, http.StatusServiceUnavailable, "this server has not been claimed yet: add it in the app to claim it")
	})
	// The claim comes from a client on another origin (a desktop webview, a
	// web app hosted elsewhere). Nothing here reads a cookie, so any origin.
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		m.ServeHTTP(rw, r)
	})
}

func (u *Unclaimed) handleClaim(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		ServerID string `json:"server_id"`
		Secret   string `json:"secret"`
	}
	if !readJSON(rw, r, &body) {
		return
	}
	if body.ServerID == "" || body.Secret == "" {
		writeErr(rw, http.StatusBadRequest, "server_id and secret are required")
		return
	}
	// One claim at a time, and only one ever.
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.claimed {
		writeErr(rw, http.StatusConflict, "this server has already been claimed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// The hub answers PUT /api/server/self only to the server those
	// credentials belong to, and only within this app: a forged or foreign
	// pair is refused here and the server stays unclaimed.
	if err := u.checkWithHub(ctx, body.ServerID, body.Secret); err != nil {
		writeErr(rw, http.StatusBadRequest, "the hub refused those credentials: "+err.Error())
		return
	}
	if err := u.OnClaim(ctx, body.ServerID, body.Secret); err != nil {
		writeErr(rw, http.StatusInternalServerError, "could not keep the claim: "+err.Error())
		return
	}
	u.claimed = true
	rw.WriteHeader(http.StatusNoContent)
}

func (u *Unclaimed) checkWithHub(ctx context.Context, id, secret string) error {
	data, _ := json.Marshal(map[string]string{"name": u.Name, "address": strings.TrimRight(u.PublicURL, "/"), "app": u.App})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(u.Issuer, "/")+"/api/server/self", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer wks_"+id+"."+secret)
	req.Header.Set("Content-Type", "application/json")
	client := u.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return &HubError{Status: resp.StatusCode, Message: e.Error}
	}
	return nil
}
