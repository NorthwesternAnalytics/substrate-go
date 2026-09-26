package trust

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Gate identity headers. DexID sets these on a successful forward-auth
// verification and Caddy copies them onto the request it forwards here
// (nw#4409, control B of nw#4408).
const (
	HeaderPersonID  = "X-DexID-Person-ID"
	HeaderIssuer    = "X-DexID-Issuer"
	HeaderSubject   = "X-DexID-Subject"
	HeaderAAL       = "X-DexID-AAL"
	HeaderAssertion = "X-DexID-Assertion"
)

// assertionType is the JWT "typ" DexID stamps on an identity assertion.
//
// CHECKED, not merely expected: it is what stops an ordinary access token being
// presented here, and an assertion being presented as an access token, even if
// key material were ever shared between the two.
const assertionType = "dexid-assertion+jwt"

// ErrNoAssertion reports that a request carried gate identity headers but no
// assertion.
//
// A DISTINCT ERROR because the four plain headers are a CLAIM by whoever can
// open a socket to this API. Without a signature they establish nothing, so the
// request is UNAUTHENTICATED — not malformed, not an error to report to the
// caller in detail, simply not signed in.
var ErrNoAssertion = errors.New("gate identity headers carry no assertion")

// GateIdentity is who DexID says the caller is, once the signature has been
// verified.
type GateIdentity struct {
	PersonID string
	Issuer   string
	Subject  string
	AAL      string

	// VerifyClass is "browser" or "api": which wall decision produced this.
	VerifyClass string

	// KeyID is the kid that signed the assertion, for logs — never a decision.
	KeyID string
}

// AssertionVerifier accepts DexID gate identity only when a valid assertion says
// so, and only when the plain headers agree with it.
//
// WHAT IT PROTECTS AGAINST, in the order the checks run:
//
//   - a forged header set with no assertion at all;
//   - an assertion signed with anything but DexID's ES256 key, including the
//     key-confusion trick of signing HS256 with the published public key;
//   - an assertion minted for ANOTHER API, replayed here;
//   - an expired one, or one minted in the future beyond the allowed skew;
//   - one already seen — replay inside its own lifetime;
//   - a valid assertion with plain headers that say something else, which is the
//     case that makes the plain headers safe to log and display.
type AssertionVerifier struct {
	keys     *keySource
	issuer   string
	audience string
	skew     time.Duration
	now      func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// AssertionConfig configures the verifier. Every field is required except Skew
// and Now.
type AssertionConfig struct {
	// JWKSURL is DexID's published key set, from its /auth/config
	// (assertion_jwks_path against assertion_issuer).
	JWKSURL string

	// Issuer is the "iss" every assertion must carry: DexID's public base URL,
	// also from /auth/config.
	Issuer string

	// Audience is THIS API's own configured audience.
	//
	// ITS OWN CONFIGURATION, NEVER THE REQUEST. Reading it from the request's
	// Host would let a caller choose which audience this API accepts, which is
	// the whole point of binding the token to one (nw#4409 seq 16198).
	Audience string

	// Skew tolerates clock difference between DexID and this API. Zero uses 30
	// seconds, half the assertion's lifetime: enough for ordinary drift, not
	// enough to double the window a stolen token is useful in.
	Skew time.Duration

	// Now is the clock. Test seam only.
	Now func() time.Time
}

// NewAssertionVerifier builds a verifier. It refuses an incomplete config rather
// than defaulting anything that decides who a caller is.
func NewAssertionVerifier(cfg AssertionConfig) (*AssertionVerifier, error) {
	switch {
	case strings.TrimSpace(cfg.JWKSURL) == "":
		return nil, errors.New("assertion verifier: JWKSURL is required")
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, errors.New("assertion verifier: Issuer is required")
	case strings.TrimSpace(cfg.Audience) == "":
		return nil, errors.New("assertion verifier: Audience is required; it is this API's own configured audience, never the request's host")
	}
	skew := cfg.Skew
	if skew == 0 {
		skew = 30 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &AssertionVerifier{
		keys:     newKeySource(cfg.JWKSURL),
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		skew:     skew,
		now:      now,
		seen:     map[string]time.Time{},
	}, nil
}

// HasGateHeaders reports whether a request presents DexID gate identity at all.
// A request with none is simply not using this path, and must not be treated as
// a failed attempt at it.
func HasGateHeaders(r *http.Request) bool {
	return r.Header.Get(HeaderPersonID) != "" || r.Header.Get(HeaderAssertion) != ""
}

// Verify establishes the caller's identity from the gate headers, or refuses.
//
// The returned error is for THIS SERVICE'S LOGS. A caller gets one
// non-revealing refusal: which of these failed tells an attacker how far they
// got, and none of it helps a legitimate client, whose request either has a
// fresh assertion from DexID or does not.
func (v *AssertionVerifier) Verify(ctx context.Context, r *http.Request) (*GateIdentity, error) {
	raw := strings.TrimSpace(r.Header.Get(HeaderAssertion))
	if raw == "" {
		return nil, ErrNoAssertion
	}

	parser := jwt.NewParser(
		// ES256 ONLY. Accepting whatever the token names is the key-confusion
		// vulnerability: an attacker signs HS256 using the published public key
		// as the HMAC secret, and a permissive verifier accepts it.
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.skew),
	)
	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != assertionType {
			return nil, fmt.Errorf("assertion typ %q is not %q", typ, assertionType)
		}
		kid, _ := t.Header["kid"].(string)
		return v.keys.keyForKid(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("assertion invalid: %w", err)
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("assertion invalid: no jti, so a replay could not be detected")
	}
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil {
		return nil, errors.New("assertion invalid: no expiry")
	}
	if err := v.remember(jti, expiry.Time); err != nil {
		return nil, err
	}

	id := &GateIdentity{
		PersonID:    stringClaim(claims, "person"),
		Issuer:      stringClaim(claims, "dexid_issuer"),
		Subject:     stringClaim(claims, "sub"),
		AAL:         stringClaim(claims, "aal"),
		VerifyClass: stringClaim(claims, "verify_class"),
	}
	if kid, _ := token.Header["kid"].(string); kid != "" {
		id.KeyID = kid
	}
	if id.PersonID == "" {
		return nil, errors.New("assertion invalid: no person claim")
	}

	// THE PLAIN HEADERS MUST AGREE. They stay on the request for logs and
	// display, and this is what makes that safe: a header that disagrees with the
	// signature is a forgery attempt or a proxy misconfiguration, and either way
	// nothing downstream should read a value the signature does not cover. An
	// ABSENT header is fine — only a CONTRADICTING one is refused, because
	// copy_headers sets only the names DexID actually returned.
	for _, check := range []struct {
		header, claim, value string
	}{
		{HeaderPersonID, "person", id.PersonID},
		{HeaderIssuer, "dexid_issuer", id.Issuer},
		{HeaderSubject, "sub", id.Subject},
		{HeaderAAL, "aal", id.AAL},
	} {
		got := r.Header.Get(check.header)
		if got != "" && got != check.value {
			return nil, fmt.Errorf("assertion invalid: %s is %q but the signed %s claim is %q",
				check.header, got, check.claim, check.value)
		}
	}
	return id, nil
}

// remember refuses a jti already seen, and forgets entries once they can no
// longer be replayed.
//
// THE CACHE IS BOUNDED BY THE TTL, not by a size limit: an assertion lives sixty
// seconds, so the set of jtis worth remembering is however many verifications
// happen in a minute. Sweeping on write keeps it that size without a goroutine
// that a library has no business starting.
func (v *AssertionVerifier) remember(jti string, expiry time.Time) error {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, exp := range v.seen {
		if exp.Before(now) {
			delete(v.seen, id)
		}
	}
	if _, replay := v.seen[jti]; replay {
		return errors.New("assertion invalid: this assertion has already been presented")
	}
	v.seen[jti] = expiry
	return nil
}

func stringClaim(claims jwt.MapClaims, name string) string {
	v, _ := claims[name].(string)
	return v
}
