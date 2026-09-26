package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// keySource fetches and caches the public keys published at one JWKS endpoint.
//
// EXTRACTED RATHER THAN COPIED (nw#4409). Two things now verify signatures
// against a published key set: the Supabase access-token Validator and the
// DexID identity-assertion verifier. This package's own doc comment explains
// what the alternative costs — steps 1 to 3 of this middleware were hand-copied
// into three backends, and the tenant-focus narrowing landed in exactly one of
// them. A second copy of "fetch, cache, re-fetch once on an unknown kid, then
// fail closed" would be the same mistake inside one package.
//
// The posture is unchanged from the Validator it came out of: an unknown kid
// triggers exactly ONE re-fetch and then fails closed, so a rotation is picked
// up without giving an attacker a way to make this fetch on demand.
type keySource struct {
	url  string
	http *http.Client

	mu   sync.Mutex
	keys map[string]any
}

func newKeySource(url string) *keySource {
	return &keySource{
		url:  url,
		http: &http.Client{Timeout: 15 * time.Second},
		keys: map[string]any{},
	}
}

// keyForKid returns the public key for kid, re-fetching the set at most once.
func (s *keySource) keyForKid(ctx context.Context, kid string) (any, error) {
	s.mu.Lock()
	key, ok := s.keys[kid]
	s.mu.Unlock()
	if ok {
		return key, nil
	}
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	key, ok = s.keys[kid]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}
	return key, nil
}

func (s *keySource) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks malformed: %w", err)
	}

	keys := map[string]any{}
	for _, k := range doc.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			}
		case "EC":
			// P-256 only, as before: another curve would be verified with an
			// algorithm this package does not allow, so admitting the key would
			// only move the refusal later.
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			}
		}
	}
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return nil
}
