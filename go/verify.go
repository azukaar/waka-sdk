package waka

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// HubClaims is the content of a token the hub made out to this server. The
// subject is this server's own subject for the user, and the profile is the
// one visible here.
type HubClaims struct {
	Handle         string `json:"handle"`
	Name           string `json:"name"`
	Bio            string `json:"bio"`
	Picture        string `json:"picture"`
	ProfileVersion int64  `json:"pv"`
	// Owner is true for the account that registered this server on the hub.
	Owner bool `json:"owner,omitempty"`
	jwt.RegisteredClaims
}

// keyCache holds each trusted hub's public keys, fetched from that hub's own
// address so one hub can never vouch for another's identities.
type keyCache struct {
	client *http.Client

	mu      sync.Mutex
	keys    map[string]map[string]ed25519.PublicKey
	fetched map[string]time.Time
	seen    map[string]time.Time // token IDs already used, until they expire
}

func newKeyCache(client *http.Client) *keyCache {
	return &keyCache{
		client:  client,
		keys:    map[string]map[string]ed25519.PublicKey{},
		fetched: map[string]time.Time{},
		seen:    map[string]time.Time{},
	}
}

func (k *keyCache) get(ctx context.Context, issuer, kid string) (ed25519.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.keys[issuer][kid]; ok {
		return key, nil
	}
	// An unknown key ID may mean the hub rotated its key, but refetching is
	// throttled so bad tokens cannot be used to hammer the hub.
	if time.Since(k.fetched[issuer]) < 30*time.Second {
		return nil, errors.New("unknown signing key")
	}
	k.fetched[issuer] = time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching hub keys: %w", err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kty, Crv, Kid, X string
		} `json:"keys"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&set) != nil {
		return nil, errors.New("fetching hub keys: bad response")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, jwk := range set.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if jwk.Kty == "OKP" && jwk.Crv == "Ed25519" && err == nil && len(raw) == ed25519.PublicKeySize {
			keys[jwk.Kid] = ed25519.PublicKey(raw)
		}
	}
	k.keys[issuer] = keys
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, errors.New("unknown signing key")
}

// firstUse records a token ID and reports whether it was new.
func (k *keyCache) firstUse(id string, exp time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	t := time.Now()
	if len(k.seen) > 10000 {
		for id, e := range k.seen {
			if t.After(e) {
				delete(k.seen, id)
			}
		}
	}
	if e, ok := k.seen[id]; ok && t.Before(e) {
		return false
	}
	k.seen[id] = exp.Add(time.Minute)
	return true
}

// VerifyHubToken checks a token from a hub: it must be signed by the issuer
// it names, that issuer must be trusted, it must be made out to this server
// and it must not have been used before.
func (w *Waka) VerifyHubToken(ctx context.Context, raw string) (*HubClaims, error) {
	claims := &HubClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if !slices.Contains(w.cfg.TrustedIssuers, claims.Issuer) {
			return nil, fmt.Errorf("issuer %q is not trusted", claims.Issuer)
		}
		kid, _ := t.Header["kid"].(string)
		return w.keys.get(ctx, claims.Issuer, kid)
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithAudience(w.cfg.ServerID),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if claims.Subject == "" || claims.ID == "" {
		return nil, errors.New("token has no subject or ID")
	}
	if !w.keys.firstUse(claims.Issuer+"|"+claims.ID, claims.ExpiresAt.Time) {
		return nil, errors.New("token was already used")
	}
	return claims, nil
}
