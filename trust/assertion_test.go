// The DexID identity assertion, verified (nw#4409, control B of nw#4408).
//
// THIS IS THE PAIR the story's acceptance asks for. Every case runs the REAL
// verifier against a real ES256 signer publishing a real JWKS over a real HTTP
// server — the far side of the wall, stood up here rather than mocked, because a
// mock of a signature check is a test of nothing.
//
// Documentation values only: example.* hosts and fixture ids.

package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	assertIssuer   = "https://id.example"
	assertAudience = "https://api.site.example"
	assertPerson   = "11111111-1111-1111-1111-111111111111"
	assertSubject  = "22222222-2222-2222-2222-222222222222"
	assertExtIss   = "https://issuer.example"
)

// dexidStub is DexID's signing half: an ES256 key and the JWKS it publishes.
type dexidStub struct {
	key    *ecdsa.PrivateKey
	kid    string
	server *httptest.Server
}

func newDexIDStub(t *testing.T) *dexidStub {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	point := elliptic.Marshal(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y) //nolint:staticcheck // the kid is the hash of the uncompressed point, as DexID derives it
	sum := sha256.Sum256(point)
	stub := &dexidStub{key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:])}

	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		size := 32
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": stub.kid, "use": "sig", "alg": "ES256",
			"x": base64.RawURLEncoding.EncodeToString(leftPad(key.PublicKey.X, size)),
			"y": base64.RawURLEncoding.EncodeToString(leftPad(key.PublicKey.Y, size)),
		}}})
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

func leftPad(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// mint signs an assertion exactly as DexID does, with whatever overrides a case
// needs.
func (d *dexidStub) mint(t *testing.T, override func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("jti: %v", err)
	}
	claims := jwt.MapClaims{
		"iss": assertIssuer, "sub": assertSubject, "aud": assertAudience,
		"person": assertPerson, "dexid_issuer": assertExtIss, "aal": "aal2",
		"verify_class": "api", "host": "api.site.example",
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
	}
	if override != nil {
		override(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = d.kid
	token.Header["typ"] = assertionType
	signed, err := token.SignedString(d.key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return signed
}

func verifierFor(t *testing.T, d *dexidStub) *AssertionVerifier {
	t.Helper()
	v, err := NewAssertionVerifier(AssertionConfig{
		JWKSURL: d.server.URL, Issuer: assertIssuer, Audience: assertAudience,
	})
	if err != nil {
		t.Fatalf("NewAssertionVerifier: %v", err)
	}
	return v
}

// gateRequest is the request Caddy forwards after a successful verification:
// the four plain headers plus the assertion.
func gateRequest(assertion string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://api.site.example/v1/widgets", nil)
	r.Header.Set(HeaderPersonID, assertPerson)
	r.Header.Set(HeaderIssuer, assertExtIss)
	r.Header.Set(HeaderSubject, assertSubject)
	r.Header.Set(HeaderAAL, "aal2")
	if assertion != "" {
		r.Header.Set(HeaderAssertion, assertion)
	}
	return r
}

func TestAssertionVerifier_DexIDsOwnAssertionIsAccepted(t *testing.T) {
	// The positive half. Without it every refusal below would also pass on a
	// verifier that refused everything.
	d := newDexIDStub(t)
	v := verifierFor(t, d)

	id, err := v.Verify(context.Background(), gateRequest(d.mint(t, nil)))
	if err != nil {
		t.Fatalf("a genuine assertion was refused: %v", err)
	}
	if id.PersonID != assertPerson || id.Subject != assertSubject || id.AAL != "aal2" {
		t.Errorf("identity = %+v, want the signed claims", id)
	}
	if id.Issuer != assertExtIss {
		t.Errorf("Issuer = %q, want the external issuer claim %q", id.Issuer, assertExtIss)
	}
	if id.VerifyClass != "api" {
		t.Errorf("VerifyClass = %q, want api", id.VerifyClass)
	}
	if id.KeyID != d.kid {
		t.Errorf("KeyID = %q, want %q", id.KeyID, d.kid)
	}
}

func TestAssertionVerifier_ForgedHeadersWithNoAssertionAreUnauthenticated(t *testing.T) {
	// ACCEPTANCE CASE 1. A complete, plausible header set that anyone who can
	// open a socket to this API could send. Without a signature it establishes
	// nothing.
	d := newDexIDStub(t)
	v := verifierFor(t, d)

	_, err := v.Verify(context.Background(), gateRequest(""))
	if err == nil {
		t.Fatal("forged headers with no assertion were accepted")
	}
	if !errors.Is(err, ErrNoAssertion) {
		t.Errorf("error = %v, want ErrNoAssertion so a caller can tell this from a malformed one", err)
	}
}

func TestAssertionVerifier_RefusesEveryTamperedAssertion(t *testing.T) {
	// ACCEPTANCE CASE 2, one subtest per way of being wrong. Each starts from a
	// GENUINE assertion and changes exactly one thing.
	other := newDexIDStub(t) // a different key, i.e. a different DexID
	cases := []struct {
		name   string
		token  func(t *testing.T, d *dexidStub) string
		expect string
	}{
		{
			"signed by another key",
			func(t *testing.T, _ *dexidStub) string { return other.mint(t, nil) },
			"unknown signing key id",
		},
		{
			"minted for another audience",
			func(t *testing.T, d *dexidStub) string {
				return d.mint(t, func(c jwt.MapClaims) { c["aud"] = "https://api.elsewhere.example" })
			},
			"aud",
		},
		{
			"minted by another issuer",
			func(t *testing.T, d *dexidStub) string {
				return d.mint(t, func(c jwt.MapClaims) { c["iss"] = "https://evil.example" })
			},
			"iss",
		},
		{
			"expired beyond the skew",
			func(t *testing.T, d *dexidStub) string {
				return d.mint(t, func(c jwt.MapClaims) {
					past := time.Now().Add(-10 * time.Minute)
					c["iat"], c["exp"] = past.Unix(), past.Add(60*time.Second).Unix()
				})
			},
			"expired",
		},
		{
			// "exp" as a substring was too weak: it also matches "no expiry"
			// AND jwt's own "exp claim is required", so either guard alone
			// satisfied it and neither was measured (mutations F4b, F4c). An
			// assertion with no expiry never stops being valid, which is the
			// one property here that must not rest on a coincidence.
			"no expiry at all",
			func(t *testing.T, d *dexidStub) string {
				return d.mint(t, func(c jwt.MapClaims) { delete(c, "exp") })
			},
			"required claim",
		},
		{
			"no jti, so a replay could not be detected",
			func(t *testing.T, d *dexidStub) string {
				return d.mint(t, func(c jwt.MapClaims) { delete(c, "jti") })
			},
			"jti",
		},
		{
			"no person claim",
			func(t *testing.T, d *dexidStub) string {
				return d.mint(t, func(c jwt.MapClaims) { delete(c, "person") })
			},
			"person",
		},
		{
			"body tampered after signing",
			func(t *testing.T, d *dexidStub) string {
				parts := strings.Split(d.mint(t, nil), ".")
				forged, _ := json.Marshal(jwt.MapClaims{
					"iss": assertIssuer, "aud": assertAudience, "person": "attacker",
					"jti": "forged", "exp": time.Now().Add(time.Minute).Unix(),
				})
				parts[1] = base64.RawURLEncoding.EncodeToString(forged)
				return strings.Join(parts, ".")
			},
			"invalid",
		},
		{
			"not a JWT at all",
			func(*testing.T, *dexidStub) string { return "not.a.token" },
			"invalid",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDexIDStub(t)
			v := verifierFor(t, d)
			_, err := v.Verify(context.Background(), gateRequest(c.token(t, d)))
			if err == nil {
				t.Fatal("the assertion was accepted")
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("error = %q, want it to mention %q", err, c.expect)
			}
		})
	}
}

func TestAssertionVerifier_TheKeyConfusionAttackFails(t *testing.T) {
	// THE ATTACK THE RULING NAMED, with a negative control. An attacker knows the
	// public key — it is published — and signs HS256 using it as the HMAC secret.
	// A verifier that trusted the token's own "alg" would accept it.
	d := newDexIDStub(t)
	v := verifierFor(t, d)

	point := elliptic.Marshal(d.key.PublicKey.Curve, d.key.PublicKey.X, d.key.PublicKey.Y) //nolint:staticcheck // the attacker uses the published point verbatim
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": assertIssuer, "aud": assertAudience, "sub": assertSubject,
		"person": "attacker", "jti": "confusion", "aal": "aal2",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	forged.Header["kid"] = d.kid
	forged.Header["typ"] = assertionType
	token, err := forged.SignedString(point)
	if err != nil {
		t.Fatalf("building the forgery: %v", err)
	}

	r := gateRequest(token)
	r.Header.Set(HeaderPersonID, "attacker")
	_, err = v.Verify(context.Background(), r)
	if err == nil {
		t.Fatal("an HS256 assertion signed with the published public key was accepted")
	}
	// THE REFUSAL MUST BE THE ALGORITHM PIN, not an accident of Go types.
	// Measured on golang-jwt/v5: pinned to ES256 the error is "signing method
	// HS256 is invalid"; UNPINNED it is "key is of invalid type: HMAC verify
	// expects []byte" — the token is still refused, but only because the keyfunc
	// returned an *ecdsa.PublicKey. Removing WithValidMethods therefore survived
	// this test until it asserted WHICH refusal it got (mutation F1), and a
	// future keyfunc that returned bytes for any reason would open the hole.
	if !strings.Contains(err.Error(), "signing method HS256 is invalid") {
		t.Errorf("error = %q; the refusal must come from the ES256 pin, not from the key's Go type", err)
	}

	// NEGATIVE CONTROL: the forgery is well-formed and verifies on its own terms,
	// so the refusal above is the algorithm pin and not a broken fixture.
	if _, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return point, nil }); err != nil {
		t.Fatalf("the forgery does not verify even unpinned, so the assertion above proves nothing: %v", err)
	}
}

func TestAssertionVerifier_ARejectedTypIsNotAnAssertion(t *testing.T) {
	// A Supabase access token, or anything else, presented in this header. The typ
	// check is what keeps the two token families apart.
	d := newDexIDStub(t)
	v := verifierFor(t, d)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": assertIssuer, "aud": assertAudience, "person": assertPerson,
		"jti": "wrong-typ", "exp": time.Now().Add(time.Minute).Unix(),
	})
	token.Header["kid"] = d.kid
	token.Header["typ"] = "JWT" // an ordinary token, correctly signed
	signed, err := token.SignedString(d.key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if _, err := v.Verify(context.Background(), gateRequest(signed)); err == nil {
		t.Fatal("a correctly signed token with the wrong typ was accepted as an assertion")
	} else if !strings.Contains(err.Error(), "typ") {
		t.Errorf("error = %q, want it to name the typ", err)
	}
}

func TestAssertionVerifier_AKeyOnAnotherCurveIsNotAdmitted(t *testing.T) {
	// A JWKS entry on another curve is SKIPPED, so its kid is unknown and the
	// assertion is refused. Admitting it would only move the refusal to the
	// signature check — but it would also mean this package's key cache held keys
	// it can never verify with, and no test noticed that until this one (mutation
	// F13).
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-384: %v", err)
	}
	kid := "p384-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-384", "kid": kid, "use": "sig", "alg": "ES384",
			"x": base64.RawURLEncoding.EncodeToString(leftPad(wrongCurve.PublicKey.X, 48)),
			"y": base64.RawURLEncoding.EncodeToString(leftPad(wrongCurve.PublicKey.Y, 48)),
		}}})
	}))
	t.Cleanup(server.Close)

	v, err := NewAssertionVerifier(AssertionConfig{
		JWKSURL: server.URL, Issuer: assertIssuer, Audience: assertAudience,
	})
	if err != nil {
		t.Fatalf("NewAssertionVerifier: %v", err)
	}

	// An ES256 assertion naming that kid: the key set offers nothing usable.
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-256: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": assertIssuer, "aud": assertAudience, "person": assertPerson,
		"jti": "p384", "exp": time.Now().Add(time.Minute).Unix(),
	})
	token.Header["kid"] = kid
	token.Header["typ"] = assertionType
	signed, err := token.SignedString(p256)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if _, err := v.Verify(context.Background(), gateRequest(signed)); err == nil {
		t.Fatal("an assertion naming a non-P-256 key was accepted")
	} else if !strings.Contains(err.Error(), "unknown signing key id") {
		t.Errorf("error = %q, want the key to have been skipped entirely", err)
	}
}

func TestAssertionVerifier_ReplayIsRefusedWithinTheLifetime(t *testing.T) {
	// ACCEPTANCE: an assertion is good ONCE. Sixty seconds is short, but a
	// captured token would otherwise be usable for all sixty of them.
	d := newDexIDStub(t)
	v := verifierFor(t, d)
	token := d.mint(t, nil)

	if _, err := v.Verify(context.Background(), gateRequest(token)); err != nil {
		t.Fatalf("the first presentation was refused: %v", err)
	}
	_, err := v.Verify(context.Background(), gateRequest(token))
	if err == nil {
		t.Fatal("the same assertion was accepted twice")
	}
	if !strings.Contains(err.Error(), "already been presented") {
		t.Errorf("error = %q, want it to name the replay", err)
	}

	// A DIFFERENT assertion for the same person still works: the refusal is per
	// token, not a lockout.
	if _, err := v.Verify(context.Background(), gateRequest(d.mint(t, nil))); err != nil {
		t.Errorf("a fresh assertion after a replay was refused: %v", err)
	}
}

func TestAssertionVerifier_PlainHeadersMustAgreeWithTheSignature(t *testing.T) {
	// ACCEPTANCE CASE 4, and the reason the plain headers are safe to keep for
	// logs and display: a header that CONTRADICTS the signature is refused, while
	// an ABSENT one is fine, because copy_headers sets only the names DexID
	// actually returned.
	d := newDexIDStub(t)

	for _, c := range []struct {
		name, header, value string
	}{
		{"a different person", HeaderPersonID, "99999999-9999-9999-9999-999999999999"},
		{"a different subject", HeaderSubject, "88888888-8888-8888-8888-888888888888"},
		{"a different issuer", HeaderIssuer, "https://attacker.example"},
		{"an upgraded assurance level", HeaderAAL, "aal3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := verifierFor(t, d)
			r := gateRequest(d.mint(t, nil))
			r.Header.Set(c.header, c.value)
			if _, err := v.Verify(context.Background(), r); err == nil {
				t.Fatalf("%s disagreed with the signature and was accepted", c.header)
			} else if !strings.Contains(err.Error(), c.header) {
				t.Errorf("error = %q, want it to name the disagreeing header", err)
			}
		})
	}

	t.Run("an absent header is not a disagreement", func(t *testing.T) {
		v := verifierFor(t, d)
		r := gateRequest(d.mint(t, nil))
		r.Header.Del(HeaderAAL)
		r.Header.Del(HeaderIssuer)
		if _, err := v.Verify(context.Background(), r); err != nil {
			t.Errorf("an absent plain header was treated as a disagreement: %v", err)
		}
	})
}

func TestAssertionVerifier_SkewIsToleratedButBounded(t *testing.T) {
	// Clocks drift; sixty-second tokens make that matter. The allowance is half
	// the lifetime, which covers ordinary drift without doubling the window a
	// stolen token is useful in.
	d := newDexIDStub(t)
	v := verifierFor(t, d)

	// Minted 20 seconds in the future: inside the 30s allowance.
	near := d.mint(t, func(c jwt.MapClaims) {
		future := time.Now().Add(20 * time.Second)
		c["iat"], c["exp"] = future.Unix(), future.Add(60*time.Second).Unix()
	})
	if _, err := v.Verify(context.Background(), gateRequest(near)); err != nil {
		t.Errorf("an assertion 20s ahead was refused: %v", err)
	}

	// Expired 45 seconds ago: outside it.
	far := d.mint(t, func(c jwt.MapClaims) {
		past := time.Now().Add(-105 * time.Second)
		c["iat"], c["exp"] = past.Unix(), past.Add(60*time.Second).Unix()
	})
	if _, err := v.Verify(context.Background(), gateRequest(far)); err == nil {
		t.Error("an assertion expired 45s beyond the allowance was accepted")
	}
}

func TestNewAssertionVerifier_RefusesAnIncompleteConfig(t *testing.T) {
	// Every one of these decides who a caller is. Defaulting any of them would
	// mean a verifier that verifies against nothing in particular.
	base := AssertionConfig{JWKSURL: "https://id.example/auth/jwks.json", Issuer: assertIssuer, Audience: assertAudience}
	for name, mutate := range map[string]func(*AssertionConfig){
		"no jwks url": func(c *AssertionConfig) { c.JWKSURL = "" },
		"no issuer":   func(c *AssertionConfig) { c.Issuer = "" },
		"no audience": func(c *AssertionConfig) { c.Audience = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := NewAssertionVerifier(cfg); err == nil {
				t.Fatal("an incomplete config was accepted")
			}
		})
	}
	if _, err := NewAssertionVerifier(base); err != nil {
		t.Errorf("a complete config was refused: %v", err)
	}
}

func TestHasGateHeaders(t *testing.T) {
	// A request using another authentication path must not look like a failed
	// attempt at this one.
	plain := httptest.NewRequest(http.MethodGet, "https://api.site.example/v1/widgets", nil)
	if HasGateHeaders(plain) {
		t.Error("a request with no gate headers was reported as using the gate")
	}
	bearer := httptest.NewRequest(http.MethodGet, "https://api.site.example/v1/widgets", nil)
	bearer.Header.Set("Authorization", "Bearer token")
	if HasGateHeaders(bearer) {
		t.Error("a Bearer request was reported as using the gate")
	}
	if !HasGateHeaders(gateRequest("token")) {
		t.Error("a gate request was not recognised")
	}
	onlyAssertion := httptest.NewRequest(http.MethodGet, "https://api.site.example/v1/widgets", nil)
	onlyAssertion.Header.Set(HeaderAssertion, "token")
	if !HasGateHeaders(onlyAssertion) {
		t.Error("a request with only an assertion was not recognised as using the gate")
	}
}
