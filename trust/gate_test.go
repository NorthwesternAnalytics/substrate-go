package trust

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The Gate, end to end over real HTTP: a request in, a refusal or a handler
// call out. These are the seams an adopting backend inherits, so they are
// tested as HTTP behaviour rather than as function calls.

const testIssuer = "https://test-project.supabase.co/auth/v1"

type testJWKS struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newTestJWKS(t *testing.T) *testJWKS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	j := &testJWKS{key: key, kid: "test-key"}
	j.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub := &j.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": j.kid,
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	}))
	t.Cleanup(j.server.Close)
	return j
}

func (j *testJWKS) mint(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": testIssuer, "sub": "8f7c2b1a-0000-4000-8000-000000000001",
		"aud": "authenticated", "email": "demo@dextech.local", "aal": "aal2",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = j.kid
	raw, err := token.SignedString(j.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// protected wires a Gate in front of a handler that records what it saw.
type protected struct {
	server *httptest.Server
	token  string
	// seen is the access context the handler observed, nil if it never ran.
	seen *Access
}

// protectedServer builds a live server whose one route is behind the Gate,
// plus a valid token for it.
func protectedServer(t *testing.T, body meContextBody, requireMFA, observe bool,
	reqs ...Requirement) *protected {
	t.Helper()
	jwks := newTestJWKS(t)
	dexid := newFakeDexID(t, body)
	gate := NewGate(GateConfig{
		Validator:  NewValidator(jwks.server.URL, testIssuer),
		DexID:      NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{ContextTTL: -1}),
		RequireMFA: requireMFA,
		Observe:    observe,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	p := &protected{token: jwks.mint(t, nil)}
	p.server = httptest.NewServer(gate.Protect(func(w http.ResponseWriter, r *http.Request) {
		p.seen = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}, reqs...))
	t.Cleanup(p.server.Close)
	return p
}

// get calls the protected route with p's own valid token.
func (p *protected) get(t *testing.T) (*http.Response, map[string]any) {
	t.Helper()
	return call(t, p.server, p.token)
}

func call(t *testing.T, server *httptest.Server, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/thing", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(t, server, req)
}

func do(t *testing.T, server *httptest.Server, req *http.Request) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func errorField(body map[string]any, field string) string {
	errObj, _ := body["error"].(map[string]any)
	value, _ := errObj[field].(string)
	return value
}

// ─── the authentication stages ───────────────────────────────────────────

func TestGateRefusesARequestWithNoBearerToken(t *testing.T) {
	p := protectedServer(t, meContextBody{PersonID: "p1"}, true, false)

	resp, body := call(t, p.server, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := errorField(body, "code"); got != CodeNotAuthenticated {
		t.Errorf("error code = %q, want %q", got, CodeNotAuthenticated)
	}
	if p.seen != nil {
		t.Error("the handler ran for an unauthenticated request")
	}
}

func TestGateRefusesAnUnverifiableToken(t *testing.T) {
	p := protectedServer(t, meContextBody{PersonID: "p1"}, true, false)

	resp, body := call(t, p.server, "not.a.jwt")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := errorField(body, "code"); got != CodeTokenInvalid {
		t.Errorf("error code = %q, want %q", got, CodeTokenInvalid)
	}
	if p.seen != nil {
		t.Error("the handler ran for an invalid token")
	}
}

// The identity plane being unreachable FAILS CLOSED, and says so with a 503
// rather than a 403: the caller did nothing wrong and retrying is the right
// advice, but nothing about them is known, so nothing may proceed.
func TestGateFailsClosedWhenTheIdentityPlaneIsUnreachable(t *testing.T) {
	jwks := newTestJWKS(t)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(dead.Close)
	gate := NewGate(GateConfig{
		Validator: NewValidator(jwks.server.URL, testIssuer),
		DexID:     NewDexIDClient(dead.URL, "app"),
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ran := false
	server := httptest.NewServer(gate.Protect(func(w http.ResponseWriter, r *http.Request) {
		ran = true
	}))
	t.Cleanup(server.Close)

	resp, body := call(t, server, jwks.mint(t, nil))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if got := errorField(body, "code"); got != CodeContextUnavailable {
		t.Errorf("error code = %q, want %q", got, CodeContextUnavailable)
	}
	if ran {
		t.Error("the handler ran with no idea who the caller was")
	}
}

// The MFA decision table, at the seam that applies it.
func TestGateMFAPolicy(t *testing.T) {
	cases := []struct {
		name       string
		requireMFA bool
		aal        string
		clientID   string
		wantStatus int
	}{
		{"session token without MFA is rejected", true, "aal1", "", http.StatusForbidden},
		{"session token with MFA passes", true, "aal2", "", http.StatusOK},
		// No MCP client can perform an MFA step-up, and its assurance was
		// established at consent time instead. Requiring aal2 here would
		// reject every delegated client outright with no path forward.
		{"delegated OAuth token passes without aal2", true, "aal1", "mcp-client", http.StatusOK},
		{"no aal claim at all is rejected", true, "", "", http.StatusForbidden},
		{"gate off lets everything through", false, "aal1", "", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwks := newTestJWKS(t)
			dexid := newFakeDexID(t, meContextBody{PersonID: "p1"})
			gate := NewGate(GateConfig{
				Validator:  NewValidator(jwks.server.URL, testIssuer),
				DexID:      NewDexIDClient(dexid.server.URL, "app"),
				RequireMFA: tc.requireMFA,
				Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			server := httptest.NewServer(gate.Protect(func(w http.ResponseWriter, r *http.Request) {}))
			t.Cleanup(server.Close)

			token := jwks.mint(t, func(m jwt.MapClaims) {
				if tc.aal == "" {
					delete(m, "aal")
				} else {
					m["aal"] = tc.aal
				}
				if tc.clientID != "" {
					m["client_id"] = tc.clientID
				}
			})
			resp, _ := call(t, server, token)
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

// ─── focus, applied at the one seam ──────────────────────────────────────

func TestGateAppliesTenantFocusBeforeTheHandlerSeesAnything(t *testing.T) {
	p := protectedServer(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member"), member("beta", "member")},
	}, false, false)

	req, _ := http.NewRequest(http.MethodGet, p.server.URL+"/v1/thing", nil)
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set(TenantFocusHeader, "beta")
	if resp, _ := do(t, p.server, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	access := p.seen
	if access == nil {
		t.Fatal("the handler saw no access context")
	}
	if got := access.TenantIDs(); len(got) != 1 || got[0] != "beta" {
		t.Errorf("handler scope = %v, want [beta] — focus must be applied before the handler runs", got)
	}
	// And authorization is untouched: rule 4 of the focus contract.
	if !access.HasTenant("alpha") {
		t.Error("focus on beta revoked membership of alpha")
	}
}

// ─── requirements ────────────────────────────────────────────────────────

func TestGateRefusesARouteRequirementWithTheClientsOwnReasonCode(t *testing.T) {
	p := protectedServer(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member")},
	}, false, false, adminOnly)

	resp, body := p.get(t)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	// THE PARITY THAT MATTERS AT RUNTIME: the code on the wire is the same
	// string the Dart FeatureDecisionEngine would have produced locally, so
	// one refusal reads identically whichever layer answered it.
	if got := errorField(body, "code"); got != ReasonRoleDenied {
		t.Errorf("error code = %q, want %q", got, ReasonRoleDenied)
	}
	if got := errorField(body, "reason"); got != ReasonRoleDenied {
		t.Errorf("error reason = %q, want %q", got, ReasonRoleDenied)
	}
	if errorField(body, "remediation") == "" {
		t.Error("the refusal carried no remediation")
	}
	if p.seen != nil {
		t.Error("the handler ran despite the requirement being refused")
	}
}

func TestGateAdmitsACallerWhoSatisfiesTheRequirement(t *testing.T) {
	p := protectedServer(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "admin")},
	}, false, false, adminOnly)

	if resp, _ := p.get(t); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if p.seen == nil {
		t.Error("the handler did not run for a caller who satisfies the requirement")
	}
}

func TestGateRefusesAnUnentitledTenantOnAFeatureRoute(t *testing.T) {
	p := protectedServer(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member", "some.other.key")},
	}, false, false, RequireFeature("demo.reports.export"))

	resp, body := p.get(t)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := errorField(body, "code"); got != ReasonTenantNotEntitled {
		t.Errorf("error code = %q, want %q", got, ReasonTenantNotEntitled)
	}
}

// Requirements compose, and the FIRST unmet one answers — so a refusal names
// one cause a person can act on rather than a list.
func TestGateEvaluatesRequirementsInOrderAndStopsAtTheFirstRefusal(t *testing.T) {
	p := protectedServer(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member")},
	}, false, false, adminOnly, RequireFeature("demo.reports.export"))

	_, body := p.get(t)
	if got := errorField(body, "code"); got != ReasonRoleDenied {
		t.Errorf("error code = %q, want the FIRST requirement's reason %q",
			got, ReasonRoleDenied)
	}
}

// OBSERVE MODE exists so an operator can disarm a newly-landed gate without a
// deploy. It downgrades decisions only — never authentication.
func TestObserveModeAllowsARefusedDecisionButNotABadToken(t *testing.T) {
	p := protectedServer(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member")},
	}, false, true, adminOnly)

	if resp, _ := p.get(t); resp.StatusCode != http.StatusOK {
		t.Error("observe mode refused a decision it was configured to only observe")
	}
	if p.seen == nil {
		t.Error("observe mode did not run the handler")
	}

	if resp, _ := call(t, p.server, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("observe mode let an unauthenticated request through with %d; it must "+
			"downgrade decisions only", resp.StatusCode)
	}
}

// A handler reached outside the Gate sees no access context, and the module's
// decision engine refuses rather than panicking on it.
func TestFromContextIsNilOutsideTheGate(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if FromContext(req.Context()) != nil {
		t.Error("an unprotected request carried an access context")
	}
}

// ─── the focus header contract ───────────────────────────────────────────

func TestReadTenantFocus(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"absent means all tenants", nil, ""},
		{"a value is read verbatim", []string{"northwesternanalytics"}, "northwesternanalytics"},
		{"padding is trimmed", []string{"  alpha \t"}, "alpha"},
		// THE ONE JUDGEMENT CALL. Read as absence, a stripped header silently
		// restores all-tenants scope — invisible in a log, and exactly the bug
		// this control exists to eliminate. Read as a focus on nothing, it
		// empties every screen: alarming, immediate, reported within a minute.
		{"present but blank narrows to nothing", []string{""}, BlankFocusSentinel},
		{"whitespace only narrows to nothing", []string{"   "}, BlankFocusSentinel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, v := range tc.values {
				r.Header.Add(TenantFocusHeader, v)
			}
			if got := ReadTenantFocus(r); got != tc.want {
				t.Errorf("ReadTenantFocus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTheBlankFocusSentinelCannotBeATenantID(t *testing.T) {
	access := Access{Tenants: []TenantMembership{member("alpha", "member")}}
	if ids := access.WithTenantFocus(BlankFocusSentinel).TenantIDs(); len(ids) != 0 {
		t.Errorf("the blank sentinel produced scope %v, want none", ids)
	}
}
