package waka

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// The calls a server makes to its hub: keeping its directory entry current,
// finding a user to share with, and posting to an inbox. Sessions never
// involve the hub.

// HubError is a refusal from the hub.
type HubError struct {
	Status  int
	Message string
}

func (e *HubError) Error() string { return fmt.Sprintf("hub: %s (%d)", e.Message, e.Status) }

// HubUser is what the hub reveals about an account to a server: its subject
// for this server (the hub gives every server its own) and the profile
// visible here.
type HubUser struct {
	ID      string `json:"id"`
	Handle  string `json:"handle"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func (w *Waka) hubDo(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.cfg.Issuer+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer wks_"+w.cfg.ServerID+"."+w.cfg.ServerSecret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := w.cfg.HTTPClient.Do(req)
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
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Register reports this server's name and address to the hub's directory.
// Call it at startup and whenever the address changes.
func (w *Waka) Register(ctx context.Context) error {
	return w.hubDo(ctx, http.MethodPut, "/api/server/self", map[string]string{
		"name": w.cfg.Name, "address": w.address(), "app": w.cfg.App,
	}, nil)
}

// LookupUser finds a Waka account of this server's app by the exact handle
// it has on this server. Someone with a different handle here than in the
// rest of the app is only found by the one used here.
func (w *Waka) LookupUser(ctx context.Context, handle string) (*HubUser, error) {
	u := &HubUser{}
	err := w.hubDo(ctx, http.MethodGet, "/api/server/users/lookup?q="+url.QueryEscape(handle), nil, u)
	if he, ok := err.(*HubError); ok && he.Status == http.StatusNotFound {
		return nil, ErrUserNotFound
	}
	return u, err
}

// send seals a payload to each of the recipient's devices and posts it to
// their hub inbox. The hub only ever sees the sealed copies.
func (w *Waka) send(ctx context.Context, kind, toSubject, fromSubject, ref string, payload any) error {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var devices []struct {
		ID        string `json:"id"`
		PublicKey string `json:"public_key"`
	}
	if err := w.hubDo(ctx, http.MethodGet, "/api/server/users/"+url.PathEscape(toSubject)+"/devices", nil, &devices); err != nil {
		return err
	}
	blobs := map[string]string{}
	for _, d := range devices {
		pub, err := base64.StdEncoding.DecodeString(d.PublicKey)
		if err != nil {
			continue
		}
		sealed, err := Seal(pub, plaintext)
		if err != nil {
			continue
		}
		blobs[d.ID] = base64.StdEncoding.EncodeToString(sealed)
	}
	return w.hubDo(ctx, http.MethodPost, "/api/server/inbox", map[string]any{
		"to": toSubject, "from_user": fromSubject, "kind": kind, "ref": ref, "key": ref, "blobs": blobs,
	}, nil)
}

// Notify sends an end-to-end encrypted notification to a user of this
// server. Only users on this server's own hub can be reached.
func (w *Waka) Notify(ctx context.Context, userID string, payload any) error {
	u, err := w.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Issuer != w.cfg.Issuer {
		return fmt.Errorf("waka: %s is on another hub", u.Handle)
	}
	return w.send(ctx, "notification", u.Subject, "", "", payload)
}

// Hint tells a user's clients that something changed here, without showing
// them anything: "album 12 changed, come and sync". It is a poke, not the
// change. A newer hint with the same key replaces an older one that was not
// handled yet, and delivery to phones is best effort, so clients must be
// able to catch up from this server by themselves.
//
// The key is visible to the hub; the payload is not. Keep content out of the
// key ("notebook:12", not a title).
func (w *Waka) Hint(ctx context.Context, userID, key string, payload any) error {
	u, err := w.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Issuer != w.cfg.Issuer {
		return fmt.Errorf("waka: %s is on another hub", u.Handle)
	}
	return w.send(ctx, "hint", u.Subject, "", key, payload)
}

func (w *Waka) serverInfo() map[string]string {
	return map[string]string{"id": w.cfg.ServerID, "name": w.cfg.Name, "address": w.address(), "app": w.cfg.App}
}
