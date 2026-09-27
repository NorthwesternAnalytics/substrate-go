// The resolver that fills nw#4423's seam by asking DexID's service route (nw#4424).
//
// Documentation values only. The "service key" here is a fixture string, never a
// real credential — and the tests assert it never appears anywhere but the header.

package trust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	fixtureServiceKey = "dxa_fixtureservicekeynotarealcredential00000"
	resolverPerson    = "11111111-1111-1111-1111-111111111111"
)

// dexidServiceStub is DexID's service route: it records what it was asked and
// answers with a context document, or the one 404.
type dexidServiceStub struct {
	server *httptest.Server

	status int
	body   any

	gotAuth  string
	gotPath  string
	gotQuery string
}

func newDexIDServiceStub(t *testing.T) *dexidServiceStub {
	t.Helper()
	s := &dexidServiceStub{status: http.StatusOK}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.gotAuth = r.Header.Get("Authorization")
		s.gotPath = r.URL.Path
		s.gotQuery = r.URL.RawQuery
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(`{"code":"not_found","message":"not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(s.body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func resolverFor(t *testing.T, stub *dexidServiceStub) *ServiceContextResolver {
	t.Helper()
	r, err := NewServiceContextResolver(stub.server.URL, fixtureServiceKey, ServiceContextOptions{})
	if err != nil {
		t.Fatalf("NewServiceContextResolver: %v", err)
	}
	return r
}

func TestServiceContextResolver_AsksAsTheAppAndReadsOneDocument(t *testing.T) {
	stub := newDexIDServiceStub(t)
	stub.body = meContextBody{
		PersonID:      resolverPerson,
		DisplayName:   "Fixture Person",
		OwnerPersonID: resolverPerson,
		PrincipalIDs:  []string{resolverPerson},
		PlatformRoles: []string{"platform.member"},
		Tenants: []TenantMembership{{
			TenantID: "tenant-1", Role: "member", Entitlements: []string{"feature.widgets"},
		}},
	}

	access, err := resolverFor(t, stub).ResolveFor(context.Background(),
		GateIdentity{PersonID: resolverPerson, AAL: "aal2", VerifyClass: "api"})
	if err != nil {
		t.Fatalf("ResolveFor: %v", err)
	}

	// The SAME translation /v1/me/context uses, so one document has one reading.
	if access.PersonID != resolverPerson || access.DisplayName != "Fixture Person" {
		t.Errorf("access = %+v, want the document's person and name", access)
	}
	if len(access.Tenants) != 1 || access.Tenants[0].TenantID != "tenant-1" {
		t.Errorf("tenants = %+v, want the document's one tenant", access.Tenants)
	}
	if !access.HasEntitlement("tenant-1", "feature.widgets") {
		t.Error("the entitlement did not survive the translation")
	}

	// It asked as the APP, on the person's path, with no app_id parameter (the
	// route refuses one).
	if stub.gotAuth != "Bearer "+fixtureServiceKey {
		t.Errorf("Authorization = %q, want the service credential as a Bearer", stub.gotAuth)
	}
	if stub.gotPath != "/v1/context/person/"+resolverPerson {
		t.Errorf("path = %q, want the service context route for that person", stub.gotPath)
	}
	if stub.gotQuery != "" {
		t.Errorf("query = %q, want none: the app is the principal, not a parameter", stub.gotQuery)
	}
}

func TestServiceContextResolver_EveryRefusalIsOneError(t *testing.T) {
	// DexID answers one 404 for an unknown principal, a revoked key and a person in
	// no tenant this app serves. It must stay ONE thing here, so nothing downstream
	// can tell a caller which it was.
	stub := newDexIDServiceStub(t)
	stub.status = http.StatusNotFound

	_, err := resolverFor(t, stub).ResolveFor(context.Background(), GateIdentity{PersonID: resolverPerson})
	if err == nil {
		t.Fatal("a 404 was accepted")
	}
	if !strings.Contains(err.Error(), ErrGateContextRefused.Error()) {
		t.Errorf("err = %v, want the single refusal", err)
	}
}

func TestServiceContextResolver_TheCredentialNeverLeavesTheHeader(t *testing.T) {
	// A credential in an error, a URL or a log is a credential that has leaked. The
	// resolver's errors are read by the Gate, which logs them.
	stub := newDexIDServiceStub(t)
	stub.status = http.StatusInternalServerError

	_, err := resolverFor(t, stub).ResolveFor(context.Background(), GateIdentity{PersonID: resolverPerson})
	if err == nil {
		t.Fatal("a 500 was accepted")
	}
	if strings.Contains(err.Error(), fixtureServiceKey) {
		t.Errorf("the error carries the credential: %v", err)
	}
	// And the path it asked for carried no credential either.
	if strings.Contains(stub.gotPath+stub.gotQuery, fixtureServiceKey) {
		t.Errorf("the request URL carries the credential: %s?%s", stub.gotPath, stub.gotQuery)
	}

	// An unreachable DexID: still no credential in the message.
	closed := newDexIDServiceStub(t)
	url := closed.server.URL
	closed.server.Close()
	r, err := NewServiceContextResolver(url, fixtureServiceKey, ServiceContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ResolveFor(context.Background(), GateIdentity{PersonID: resolverPerson})
	if err == nil {
		t.Fatal("an unreachable DexID was accepted")
	}
	if strings.Contains(err.Error(), fixtureServiceKey) {
		t.Errorf("the unreachable error carries the credential: %v", err)
	}
}

func TestNewServiceContextResolver_RefusesWithoutACredential(t *testing.T) {
	// WITHOUT ONE THE GATE MUST REFUSE, not silently resolve nothing: an app that
	// forgot to configure its service credential would otherwise look like an app
	// whose users have no tenants.
	if _, err := NewServiceContextResolver("https://id.example", "", ServiceContextOptions{}); err == nil {
		t.Error("a resolver with no credential was built")
	}
	if _, err := NewServiceContextResolver("", fixtureServiceKey, ServiceContextOptions{}); err == nil {
		t.Error("a resolver with no base URL was built")
	}
}

func TestServiceContextResolver_NoPersonInTheAssertionIsARefusal(t *testing.T) {
	stub := newDexIDServiceStub(t)
	if _, err := resolverFor(t, stub).ResolveFor(context.Background(), GateIdentity{}); err == nil {
		t.Error("an assertion with no person was resolved")
	}
	if stub.gotPath != "" {
		t.Errorf("DexID was asked anyway, about %q", stub.gotPath)
	}
}

func TestServiceContextResolver_MalformedDocumentIsNotAnEmptyAccess(t *testing.T) {
	// An unreadable document must not become "a person with no tenants", which a
	// requirement would then refuse as a missing entitlement rather than as an
	// identity-plane fault.
	stub := newDexIDServiceStub(t)
	stub.body = json.RawMessage(`{"tenants": "not an array"}`)

	if _, err := resolverFor(t, stub).ResolveFor(context.Background(),
		GateIdentity{PersonID: resolverPerson}); err == nil {
		t.Error("a malformed context document was accepted")
	}
}

func TestServiceContextResolver_IsAGateContextResolver(t *testing.T) {
	// It fills nw#4423's seam, which is the whole point.
	stub := newDexIDServiceStub(t)
	var _ GateContextResolver = resolverFor(t, stub)
}
