package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the validated JWT claims a substrate backend consumes.
type Claims struct {
	Subject string // Supabase user UUID — the stable person key
	Email   string
	// AAL is the authenticator assurance level ("aal1" | "aal2"), present
	// once MFA is in play. Checked against the Gate's RequireMFA policy.
	AAL string
	// ClientID is set only on tokens minted through Supabase's OAuth 2.1
	// server -- an MCP client acting for a person, rather than that person's
	// own browser session. Empty for an ordinary session token.
	//
	// The Gate uses it to tell a delegated token from a session token, which
	// changes what the AAL check can meaningfully assert about it.
	ClientID string
}

// Delegated reports that this token was minted through the OAuth 2.1 server
// for a client acting on a person's behalf, rather than being that person's
// own browser session token.
func (c Claims) Delegated() bool { return c.ClientID != "" }

// Validator verifies Supabase access tokens against the project's published
// JWKS. Algorithm allowlist (RS256/ES256 only), issuer check, audience
// "authenticated", unknown-kid triggers exactly one re-fetch then fails
// closed — the same security posture as dexid's own validator, which is where
// this approach was proven before it was extracted here.
type Validator struct {
	jwksURL string
	issuer  string
	http    *http.Client

	mu   sync.Mutex
	keys map[string]any
}

// NewValidator creates a validator for tokens from issuer, verified against
// jwksURL.
func NewValidator(jwksURL, issuer string) *Validator {
	return &Validator{
		jwksURL: jwksURL,
		issuer:  issuer,
		http:    &http.Client{Timeout: 15 * time.Second},
		keys:    map[string]any{},
	}
}

// ValidateJWT verifies signature, algorithm, issuer, audience, and expiry,
// returning the subject and email claims.
func (v *Validator) ValidateJWT(ctx context.Context, raw string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
		jwt.WithAudience("authenticated"),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.keyForKid(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("token invalid: %w", err)
	}
	sub, _ := claims.GetSubject()
	if sub == "" {
		return nil, errors.New("token invalid: missing subject")
	}
	email, _ := claims["email"].(string)
	aal, _ := claims["aal"].(string)
	clientID, _ := claims["client_id"].(string)
	return &Claims{Subject: sub, Email: email, AAL: aal, ClientID: clientID}, nil
}

func (v *Validator) keyForKid(ctx context.Context, kid string) (any, error) {
	v.mu.Lock()
	key, ok := v.keys[kid]
	v.mu.Unlock()
	if ok {
		return key, nil
	}
	if err := v.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	v.mu.Lock()
	key, ok = v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}
	return key, nil
}

func (v *Validator) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
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
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}
