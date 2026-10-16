package waka

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A hub that knows one server, srv1 with secret good, of the app notes.
func claimHub(t *testing.T) *httptest.Server {
	h := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/server/self" {
			http.NotFound(rw, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer wks_srv1.good" {
			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(map[string]string{"error": "unknown server"})
			return
		}
		rw.Write([]byte(`{}`))
	}))
	t.Cleanup(h.Close)
	return h
}

func claimCall(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/waka/claim", strings.NewReader(body)))
	return rec
}

func TestUnclaimedSaysSoAndRefusesEverythingElse(t *testing.T) {
	u := &Unclaimed{Issuer: "http://hub/", App: "notes", Name: "Mine"}
	rec := httptest.NewRecorder()
	u.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/waka-server", nil))
	var info map[string]any
	json.Unmarshal(rec.Body.Bytes(), &info)
	if info["claimed"] != false || info["issuer"] != "http://hub" || info["app"] != "notes" {
		t.Fatalf("info = %v", info)
	}
	rec = httptest.NewRecorder()
	u.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/server", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unclaimed server answered %d", rec.Code)
	}
}

func TestFirstClaimWinsAndOnlyWithCredentialsTheHubAccepts(t *testing.T) {
	hub := claimHub(t)
	var kept []string
	u := &Unclaimed{Issuer: hub.URL, App: "notes", Name: "Mine", PublicURL: "http://srv",
		OnClaim: func(_ context.Context, id, secret string) error { kept = append(kept, id+"/"+secret); return nil }}
	h := u.Handler()

	if rec := claimCall(t, h, `{"server_id":"srv1","secret":"bad"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("forged credentials: %d %s", rec.Code, rec.Body)
	}
	if len(kept) != 0 {
		t.Fatalf("kept forged credentials: %v", kept)
	}
	if rec := claimCall(t, h, `{"server_id":"srv1","secret":"good"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body)
	}
	if rec := claimCall(t, h, `{"server_id":"srv1","secret":"good"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second claim: %d", rec.Code)
	}
	if len(kept) != 1 || kept[0] != "srv1/good" {
		t.Fatalf("kept = %v", kept)
	}
}
