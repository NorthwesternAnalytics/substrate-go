// trust.Gate admitting DexID gate identity (nw#4423).
//
// THE PAIR the story asks for: a real ES256 signer publishing a real JWKS over a
// real HTTP server, verified by the real AssertionVerifier, through the real Gate.
// The only double is the context resolver, because the endpoint behind it does not
// exist yet (nw#4423 seq 16243).
//
// Documentation values only: example.* hosts and fixture ids.

package trust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// gateAccess is what a resolver returns for the fixture person: one tenant, one
// membership, enough for a requirement to be judged against.
func gateAccess() *Access {
	return &Access{
		PersonID:      assertPerson,
		DisplayName:   "Fixture Person",
		OwnerPersonID: assertPerson,
		PrincipalIDs:  []string{assertPerson},
		Tenants: []TenantMembership{{
			TenantID: "tenant-1", Role: "member",
			Entitlements: []string{"feature.widgets"},
		}},
	}
}

// gateOnlyGate builds a Gate whose ONLY way in is gate identity: no validator is
// needed because these requests carry no Bearer.
func gateOnlyGate(t *testing.T, d *dexidStub, resolver GateContextResolver) *Gate {
	t.Helper()
	return NewGate(GateConfig{
		Assertions:  verifierFor(t, d),
		GateContext: resolver,
	})
}

func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		access := FromContext(r.Context())
		if access == nil {
			http.Error(w, "no access in context", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"person":       access.PersonID,
			"auth_kind":    string(access.AuthKind),
			"verify_class": access.VerifyClass,
			"kid":          access.AssertionKeyID,
			"aal":          access.AAL,
			"bearer":       access.BearerToken,
		})
	}
}

func TestGate_AValidAssertionAuthenticatesAsThatPerson(t *testing.T) {
	d := newDexIDStub(t)
	resolved := 0
	gate := gateOnlyGate(t, d, GateContextResolverFunc(func(_ context.Context, id GateIdentity) (*Access, error) {
		resolved++
		if id.PersonID != assertPerson {
			t.Errorf("the resolver was asked about %q, want %q", id.PersonID, assertPerson)
		}
		return gateAccess(), nil
	}))

	w := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(w, gateRequest(d.mint(t, nil)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("handler body: %v", err)
	}
	for field, want := range map[string]string{
		"person":       assertPerson,
		"auth_kind":    string(AuthGate),
		"verify_class": "api",
		"kid":          d.kid,
		"aal":          "aal2",
	} {
		if got[field] != want {
			t.Errorf("%s = %v, want %q", field, got[field], want)
		}
	}
	// NO BEARER TOKEN. Access.BearerToken exists so a handler can act AS THE
	// CALLER; there is no such token here, and a stale or borrowed one would let a
	// handler act with credentials that are not the caller's.
	if got["bearer"] != "" {
		t.Errorf("bearer = %v, want empty on the gate path", got["bearer"])
	}
	if resolved != 1 {
		t.Errorf("the resolver was called %d times, want 1", resolved)
	}
}

func TestGate_TheSignatureOverridesWhateverTheResolverSays(t *testing.T) {
	// THE FIXTURE MUST DISAGREE, or nothing is measured. With a resolver that
	// returned the same person id and no bearer token, deleting both enforcement
	// lines changed nothing (mutations H5, H6): the code and the fixture agreed,
	// so the code was never doing the work.
	//
	// WHAT IS ENFORCED. The signed person id wins over anything a resolver
	// reports — a resolver keyed on that id cannot legitimately disagree, and if
	// it ever did, the signature is what DexID vouched for. And no bearer token
	// survives onto a gate Access whatever the resolver put there: BearerToken
	// exists so a handler can act AS THE CALLER, and there is no caller token on
	// this path, so a borrowed one would let a handler act with credentials that
	// are not the caller's.
	d := newDexIDStub(t)
	gate := gateOnlyGate(t, d, GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
		access := gateAccess()
		access.PersonID = "77777777-7777-7777-7777-777777777777"
		access.BearerToken = "a-token-the-resolver-had-no-business-with"
		access.AuthKind = AuthBearer
		return access, nil
	}))

	w := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(w, gateRequest(d.mint(t, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("handler body: %v", err)
	}
	if got["person"] != assertPerson {
		t.Errorf("person = %v, want the SIGNED %q, not the resolver's", got["person"], assertPerson)
	}
	if got["bearer"] != "" {
		t.Errorf("bearer = %v; a token the resolver supplied survived onto a gate Access", got["bearer"])
	}
	if got["auth_kind"] != string(AuthGate) {
		t.Errorf("auth_kind = %v, want %q even though the resolver claimed otherwise", got["auth_kind"], AuthGate)
	}
}

func TestGate_EveryGateFailureIsTheSameNonRevealing401(t *testing.T) {
	// ONE REFUSAL FOR EVERY FAILURE. Which one it was tells an attacker how far
	// they got and helps a legitimate caller not at all. The body must be
	// byte-identical across all of them, and identical to the plain "no Bearer"
	// refusal, or the difference itself is the oracle.
	d := newDexIDStub(t)
	resolver := GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
		return gateAccess(), nil
	})

	bodies := map[string]string{}
	record := func(name string, r *http.Request) {
		gate := gateOnlyGate(t, d, resolver)
		w := httptest.NewRecorder()
		gate.Protect(okHandler()).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d (%s), want 401", name, w.Code, w.Body.String())
		}
		bodies[name] = w.Body.String()
	}

	record("no assertion at all", gateRequest(""))
	record("not a token", gateRequest("not.a.token"))
	record("another key", gateRequest(newDexIDStub(t).mint(t, nil)))
	record("wrong audience", gateRequest(d.mint(t, func(c jwt.MapClaims) {
		c["aud"] = "https://api.elsewhere.example"
	})))
	record("expired", gateRequest(d.mint(t, func(c jwt.MapClaims) {
		past := time.Now().Add(-10 * time.Minute)
		c["iat"], c["exp"] = past.Unix(), past.Add(60*time.Second).Unix()
	})))
	disagreeing := gateRequest(d.mint(t, nil))
	disagreeing.Header.Set(HeaderPersonID, "99999999-9999-9999-9999-999999999999")
	record("a header disagreeing with the signature", disagreeing)

	// And the plain no-credentials refusal, which must look the same.
	plainGate := gateOnlyGate(t, d, resolver)
	plain := httptest.NewRecorder()
	plainGate.Protect(okHandler()).ServeHTTP(plain,
		httptest.NewRequest(http.MethodGet, "https://api.site.example/v1/widgets", nil))
	bodies["no credentials at all"] = plain.Body.String()

	var reference string
	for name, body := range bodies {
		if reference == "" {
			reference = body
			continue
		}
		if body != reference {
			t.Errorf("%s produced a different body (%q) from another refusal (%q); "+
				"the difference is an oracle", name, body, reference)
		}
	}
	if !strings.Contains(reference, CodeNotAuthenticated) {
		t.Errorf("the refusal body %q does not carry %q", reference, CodeNotAuthenticated)
	}
}

func TestGate_AReplayedAssertionIsRefused(t *testing.T) {
	d := newDexIDStub(t)
	gate := gateOnlyGate(t, d, GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
		return gateAccess(), nil
	}))
	token := d.mint(t, nil)

	first := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(first, gateRequest(token))
	if first.Code != http.StatusOK {
		t.Fatalf("the first presentation = %d (%s), want 200", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(second, gateRequest(token))
	if second.Code != http.StatusUnauthorized {
		t.Errorf("a replayed assertion = %d, want 401", second.Code)
	}
}

func TestGate_WithNoVerifierConfiguredGateHeadersAreIgnored(t *testing.T) {
	// Item (4). A deployment that has not turned this on behaves EXACTLY as it did
	// before: the headers are not trusted, and they are not even an attempt.
	d := newDexIDStub(t)
	gate := NewGate(GateConfig{}) // no Assertions, no GateContext

	w := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(w, gateRequest(d.mint(t, nil)))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d (%s), want 401", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), CodeNotAuthenticated) {
		t.Errorf("body = %q, want the ordinary not-authenticated refusal", w.Body.String())
	}
	// And it is the SAME refusal as a request with no headers at all, so an
	// unconfigured deployment does not advertise that the path exists.
	plain := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(plain,
		httptest.NewRequest(http.MethodGet, "https://api.site.example/v1/widgets", nil))
	if plain.Body.String() != w.Body.String() {
		t.Errorf("an unconfigured gate answers gate headers differently (%q) from no headers (%q)",
			w.Body.String(), plain.Body.String())
	}
}

func TestGate_AVerifiedAssertionWithNoResolverFailsClosed(t *testing.T) {
	// The assertion is valid and this service cannot establish what the person
	// may reach. Admitting them would cross a tenant boundary; 503 says the
	// caller did nothing wrong and retrying is the right advice.
	d := newDexIDStub(t)
	gate := NewGate(GateConfig{Assertions: verifierFor(t, d)}) // no GateContext

	w := httptest.NewRecorder()
	gate.Protect(okHandler()).ServeHTTP(w, gateRequest(d.mint(t, nil)))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (%s), want 503", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), CodeContextUnavailable) {
		t.Errorf("body = %q, want %q", w.Body.String(), CodeContextUnavailable)
	}
}

func TestGate_AResolverFailureIsNotAnAdmission(t *testing.T) {
	d := newDexIDStub(t)
	for name, resolver := range map[string]GateContextResolver{
		"an error": GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
			return nil, context.DeadlineExceeded
		}),
		// Neither an Access nor an error: a resolver bug, and the gate must not
		// dereference its way into admitting a caller with no context at all.
		"nothing at all": GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
			return nil, nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			gate := gateOnlyGate(t, d, resolver)
			w := httptest.NewRecorder()
			gate.Protect(okHandler()).ServeHTTP(w, gateRequest(d.mint(t, nil)))
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d (%s), want 503", w.Code, w.Body.String())
			}
		})
	}
}

func TestGate_TheRequirementsAreJudgedOnTheGatePathToo(t *testing.T) {
	// THE FAILURE THIS GUARDS AGAINST is a second copy of the requirements loop
	// that quietly omits a check. The gate path shares runProtected with the
	// Bearer path, and this proves it: the same requirement that allows a
	// member refuses a caller without the entitlement.
	d := newDexIDStub(t)
	allowed := gateOnlyGate(t, d, GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
		return gateAccess(), nil
	}))
	w := httptest.NewRecorder()
	allowed.Protect(okHandler(), RequireFeature("feature.widgets")).
		ServeHTTP(w, gateRequest(d.mint(t, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("an entitled gate caller = %d (%s), want 200", w.Code, w.Body.String())
	}

	withoutIt := gateOnlyGate(t, d, GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
		access := gateAccess()
		access.Tenants[0].Entitlements = nil
		return access, nil
	}))
	w = httptest.NewRecorder()
	withoutIt.Protect(okHandler(), RequireFeature("feature.widgets")).
		ServeHTTP(w, gateRequest(d.mint(t, nil)))
	if w.Code == http.StatusOK {
		t.Error("a gate caller without the entitlement reached the handler; the gate path skips requirements")
	}
}

func TestGate_TenantFocusNarrowsTheGatePathToo(t *testing.T) {
	// Focus is applied once, at the seam, for BOTH paths — the omission this
	// package exists to make unavailable.
	d := newDexIDStub(t)
	gate := gateOnlyGate(t, d, GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
		access := gateAccess()
		access.Tenants = append(access.Tenants, TenantMembership{
			TenantID: "tenant-2", Role: "member", Entitlements: []string{"feature.widgets"},
		})
		return access, nil
	}))

	var seen []string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context()).TenantIDs()
	})
	r := gateRequest(d.mint(t, nil))
	r.Header.Set("X-Tenant-Focus", "tenant-2")

	gate.Protect(handler.ServeHTTP).ServeHTTP(httptest.NewRecorder(), r)
	if len(seen) != 1 || seen[0] != "tenant-2" {
		t.Errorf("TenantIDs() = %v, want just the focused tenant", seen)
	}
}
