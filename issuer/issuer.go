// Package issuer defines the authentication-only seam between a substrate
// identity source and DexID. It deliberately contains no authorization
// vocabulary: tenants, roles, groups, entitlements and product scopes belong
// to DexID policy after a principal has been bound.
package issuer

import (
	"context"
	"time"
)

// Assertion is the complete provider-neutral authentication statement.
// Issuer and Subject together are the identity key; Name and Email are hints.
type Assertion struct {
	Issuer    string
	Subject   string
	Name      string
	Email     string
	AMR       []string
	AAL       string
	AuthTime  time.Time
	ActingFor string
	ClientID  string
}

// Principal is the canonical DexID result of binding an assertion.
type Principal struct {
	PersonID string
	Created  bool
}

// Binder maps an authenticated (issuer, subject) to the canonical principal.
type Binder interface {
	Bind(context.Context, Assertion) (Principal, error)
}

// Issuer validates one presented credential and returns only authentication
// facts. Policy and authorization are intentionally not part of this seam.
type Issuer interface {
	Validate(context.Context, string) (Assertion, error)
}

type Metadata struct {
	Issuer, AuthorizationEndpoint, TokenEndpoint, IntrospectionEndpoint string
	DeviceAuthorizationEndpoint                                         string
}

type ClientRegistration struct {
	ClientID                string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	Public                  bool
}

type AuthorizationRequest struct {
	ClientID, RedirectURI, State, Nonce, CodeChallenge string
	Scopes, Resources                                  []string
}

type AuthorizationResult struct{ Code, State string }

type TokenRequest struct {
	GrantType, Code, RedirectURI, CodeVerifier, ClientID string
	RefreshToken, DeviceCode                             string
	Resources                                            []string
}

type TokenSet struct {
	AccessToken, IDToken, RefreshToken, TokenType string
	ExpiresIn                                     time.Duration
}

type Introspection struct {
	Active    bool
	Assertion Assertion
	ExpiresAt time.Time
}

type DeviceRequest struct {
	ClientID          string
	Scopes, Resources []string
}

type DeviceAuthorization struct {
	DeviceCode, UserCode, VerificationURI string
	ExpiresIn, Interval                   time.Duration
}

// AuthorizationServer is the optional OAuth/OIDC protocol surface an issuer
// can expose. The narrow Issuer interface remains sufficient for validation.
type AuthorizationServer interface {
	Metadata(context.Context) (Metadata, error)
	Register(context.Context, ClientRegistration) (ClientRegistration, error)
	Authorize(context.Context, AuthorizationRequest) (AuthorizationResult, error)
	Token(context.Context, TokenRequest) (TokenSet, error)
	Introspect(context.Context, string) (Introspection, error)
	Device(context.Context, DeviceRequest) (DeviceAuthorization, error)
}

type SessionRequest struct {
	Principal Principal
	Assertion Assertion
	ExpiresAt time.Time
}

type Session struct {
	ID        string
	ExpiresAt time.Time
}

// SessionIssuer creates a server-held session after binding. It does not
// decide what the principal may do.
type SessionIssuer interface {
	IssueSession(context.Context, SessionRequest) (Session, error)
}
