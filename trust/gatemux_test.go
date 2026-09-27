package trust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGateMuxRefusesRoutesOutsideItsConstructionContract(t *testing.T) {
	t.Run("undeclared public route", func(t *testing.T) {
		m := NewGateMux(NewGate(GateConfig{}), "GET /health")
		mustPanicWith(t, "undeclared public route", func() {
			m.Public("GET /version", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		})
	})

	t.Run("duplicate route", func(t *testing.T) {
		m := NewGateMux(NewGate(GateConfig{}), "GET /health")
		m.Public("GET /health", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		mustPanicWith(t, "already mounted", func() {
			m.Public("GET /health", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		})
	})

	t.Run("unmounted public declaration", func(t *testing.T) {
		m := NewGateMux(NewGate(GateConfig{}), "GET /health", "GET /version")
		m.Public("GET /health", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "GET /version") {
			t.Fatalf("Validate() = %v, want the unmounted declaration", err)
		}
	})
}

func TestGateMuxRoutesIsAnImmutableInventory(t *testing.T) {
	m := NewGateMux(NewGate(GateConfig{}), "GET /health")
	m.Public("GET /health", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	m.Gated("GET /v1/widgets", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}

	routes := m.Routes()
	if len(routes) != 2 || routes[0] != (Route{"GET /health", RoutePublic}) ||
		routes[1] != (Route{"GET /v1/widgets", RouteGated}) {
		t.Fatalf("Routes() = %#v", routes)
	}
	routes[0].Pattern = "GET /changed"
	if got := m.Routes()[0].Pattern; got != "GET /health" {
		t.Fatalf("mutating returned metadata changed the router: %q", got)
	}
}

func TestGateMuxNativeBearerPair(t *testing.T) {
	jwks := newTestJWKS(t)
	dexid := newFakeDexID(t, meContextBody{PersonID: "p1"})
	gate := NewGate(GateConfig{
		Validator: NewValidator(jwks.server.URL, testIssuer),
		DexID:     NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{ContextTTL: -1}),
	})
	runs := 0
	m := NewGateMux(gate)
	m.Gated("GET /v1/widgets", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		runs++
		w.WriteHeader(http.StatusNoContent)
	}))

	valid := jwks.mint(t, nil)
	cases := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{"valid", valid, http.StatusNoContent},
		{"invalid", "not.a.jwt", http.StatusUnauthorized},
		{"expired", jwks.mint(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), http.StatusUnauthorized},
		{"wrong audience", jwks.mint(t, func(c jwt.MapClaims) { c["aud"] = "another-audience" }), http.StatusUnauthorized},
	}
	var refusal string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/widgets", nil)
			r.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d (%s), want %d", w.Code, w.Body.String(), tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if !strings.Contains(w.Body.String(), CodeTokenInvalid) {
					t.Errorf("body = %q, want the non-revealing %q refusal", w.Body.String(), CodeTokenInvalid)
				}
				if refusal == "" {
					refusal = w.Body.String()
				} else if w.Body.String() != refusal {
					t.Errorf("body = %q, want byte-identical refusal %q", w.Body.String(), refusal)
				}
			}
		})
	}
	if runs != 1 {
		t.Fatalf("handler ran %d times, want only the valid bearer", runs)
	}
}

func TestGateMuxSignedAssertionPairAndBearerPrecedence(t *testing.T) {
	d := newDexIDStub(t)
	bearerJWKS := newTestJWKS(t)
	bearerDexID := newFakeDexID(t, meContextBody{PersonID: "bearer-person"})
	resolverCalls := 0
	gate := NewGate(GateConfig{
		Validator:  NewValidator(bearerJWKS.server.URL, testIssuer),
		DexID:      NewDexIDClientWith(bearerDexID.server.URL, "app", DexIDOptions{ContextTTL: -1}),
		Assertions: verifierFor(t, d),
		GateContext: GateContextResolverFunc(func(context.Context, GateIdentity) (*Access, error) {
			resolverCalls++
			return gateAccess(), nil
		}),
	})
	m := NewGateMux(gate)
	m.Gated("GET /v1/widgets", okHandler())

	valid := httptest.NewRecorder()
	m.ServeHTTP(valid, gateRequest(d.mint(t, nil)))
	if valid.Code != http.StatusOK {
		t.Fatalf("valid assertion = %d (%s), want 200", valid.Code, valid.Body.String())
	}

	plain := httptest.NewRecorder()
	m.ServeHTTP(plain, gateRequest(""))
	if plain.Code != http.StatusUnauthorized || !strings.Contains(plain.Body.String(), CodeNotAuthenticated) {
		t.Fatalf("plain headers = %d (%s), want non-revealing 401", plain.Code, plain.Body.String())
	}

	mismatchReq := gateRequest(d.mint(t, nil))
	mismatchReq.Header.Set(HeaderPersonID, "99999999-9999-9999-9999-999999999999")
	mismatch := httptest.NewRecorder()
	m.ServeHTTP(mismatch, mismatchReq)
	if mismatch.Code != http.StatusUnauthorized || mismatch.Body.String() != plain.Body.String() {
		t.Fatalf("mismatched headers = %d (%s), want same refusal as plain headers %q",
			mismatch.Code, mismatch.Body.String(), plain.Body.String())
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver called %d times, want only the genuine assertion", resolverCalls)
	}

	bothRequest := gateRequest(d.mint(t, nil))
	bothRequest.Header.Set("Authorization", "Bearer "+bearerJWKS.mint(t, nil))
	both := httptest.NewRecorder()
	m.ServeHTTP(both, bothRequest)
	if both.Code != http.StatusOK || !strings.Contains(both.Body.String(), `"auth_kind":"bearer"`) {
		t.Fatalf("Bearer plus assertion = %d (%s), want Bearer admission", both.Code, both.Body.String())
	}
	if resolverCalls != 1 {
		t.Fatalf("gate resolver called %d times; the assertion displaced or supplemented Bearer", resolverCalls)
	}
}

func mustPanicWith(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		got := recover()
		if got == nil || !strings.Contains(got.(string), want) {
			t.Fatalf("panic = %v, want text containing %q", got, want)
		}
	}()
	fn()
}
