package trust

import (
	"context"
	"errors"
	"fmt"

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
	issuer string
	keys   *keySource
}

// NewValidator creates a validator for tokens from issuer, verified against
// jwksURL.
func NewValidator(jwksURL, issuer string) *Validator {
	return &Validator{issuer: issuer, keys: newKeySource(jwksURL)}
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
		return v.keys.keyForKid(ctx, kid)
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
