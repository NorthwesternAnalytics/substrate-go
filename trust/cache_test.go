package trust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The DexID context cache. It is the one piece of this module that trades
// correctness for load, so the trade has to be pinned: what it saves, how
// stale it may be, and what it must never do.

type fakeDexID struct {
	server *httptest.Server

	mu    sync.Mutex
	calls int
	body  meContextBody
}

func newFakeDexID(t *testing.T, body meContextBody) *fakeDexID {
	t.Helper()
	f := &fakeDexID{body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me/context", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls++
		current := f.body
		f.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(current)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeDexID) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeDexID) setBody(body meContextBody) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = body
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestContextIsFetchedOnceWithinTheTTL(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{PersonID: "p1"})
	clock := &fakeClock{t: time.Unix(1000, 0)}
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{
		ContextTTL: 30 * time.Second, Now: clock.now,
	})

	for i := 0; i < 5; i++ {
		if _, err := client.FetchContext(context.Background(), "tok"); err != nil {
			t.Fatalf("FetchContext: %v", err)
		}
	}
	if got := dexid.callCount(); got != 1 {
		t.Errorf("identity plane called %d times for 5 requests with one token, want 1", got)
	}
	if hits, misses := client.CacheStats(); hits != 4 || misses != 1 {
		t.Errorf("cache stats = %d hits / %d misses, want 4/1", hits, misses)
	}
}

// A CHANGE MUST ARRIVE WITHIN THE TTL. This is the wave's own verification
// criterion — flip a plan, see the API's answer change — and it is the reason
// the TTL is short rather than absent.
func TestAnEntitlementChangeTakesEffectAfterTheTTL(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member")},
	})
	clock := &fakeClock{t: time.Unix(1000, 0)}
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{
		ContextTTL: 30 * time.Second, Now: clock.now,
	})

	before, err := client.FetchContext(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if Decide(before, reports).Allowed() {
		t.Fatal("allowed before the entitlement was granted")
	}

	// A plan is assigned in DexID.
	dexid.setBody(meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member", "demo.reports.export")},
	})

	// Still cached: the old answer stands, and that is the accepted cost.
	stale, _ := client.FetchContext(context.Background(), "tok")
	if Decide(stale, reports).Allowed() {
		t.Error("the new entitlement was visible before the TTL elapsed; the cache is not caching")
	}

	clock.advance(31 * time.Second)
	fresh, err := client.FetchContext(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if !Decide(fresh, reports).Allowed() {
		t.Error("the entitlement was still invisible after the TTL elapsed — a plan flip " +
			"would never take effect")
	}
}

// REVOCATION IS BOUNDED BY THE TTL TOO, in the other direction. DexID
// deliberately derives an agent's access live so that "access the owner loses,
// the agent loses on its very next call"; the cache may delay that, but only
// by the TTL.
func TestRevokedAccessDisappearsAfterTheTTL(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "admin")},
	})
	clock := &fakeClock{t: time.Unix(1000, 0)}
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{
		ContextTTL: 30 * time.Second, Now: clock.now,
	})

	if _, err := client.FetchContext(context.Background(), "tok"); err != nil {
		t.Fatal(err)
	}
	dexid.setBody(meContextBody{PersonID: "p1"}) // removed from every tenant

	clock.advance(31 * time.Second)
	after, err := client.FetchContext(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(after.AuthorizedTenantIDs()) != 0 {
		t.Error("a caller removed from every tenant still held membership after the TTL")
	}
}

// Two callers are two contexts. A cache keyed wrongly here would be a
// cross-account data leak, not a performance bug.
func TestDifferentTokensNeverShareAContext(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{PersonID: "first"})
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{})

	first, err := client.FetchContext(context.Background(), "token-a")
	if err != nil {
		t.Fatal(err)
	}
	dexid.setBody(meContextBody{PersonID: "second"})
	second, err := client.FetchContext(context.Background(), "token-b")
	if err != nil {
		t.Fatal(err)
	}
	if first.PersonID == second.PersonID {
		t.Fatalf("two tokens resolved to the same person (%q) — the cache is keyed wrongly",
			first.PersonID)
	}
}

// THE RAW TOKEN IS NEVER A MAP KEY. It is a live credential; a process-long
// map of them is a set of credentials waiting to be found in a heap dump.
func TestTheCacheDoesNotHoldRawTokens(t *testing.T) {
	cache := newContextCache(time.Minute, nil)
	cache.put("super-secret-token", Access{PersonID: "p1"})

	for key := range cache.entries {
		if strings.Contains(key, "super-secret-token") {
			t.Fatal("the raw bearer token appears as a cache key")
		}
	}
}

// A cached context must be handed out as a COPY. The Gate stamps the request's
// bearer token and tenant focus onto what it gets back; if that were the
// cached value, the next request on the same token would inherit the previous
// request's scope — a focus leak between requests.
func TestACachedContextIsACopyAndCarriesNoPerRequestState(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member"), member("beta", "member")},
	})
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{})

	first, err := client.FetchContext(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	first.BearerToken = "tok"
	focused := first.WithTenantFocus("alpha")
	if len(focused.TenantIDs()) != 1 {
		t.Fatalf("focus did not narrow: %v", focused.TenantIDs())
	}

	second, err := client.FetchContext(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if second.TenantFocus() != "" {
		t.Errorf("a cached context arrived pre-focused on %q — the previous request's scope leaked",
			second.TenantFocus())
	}
	if second.BearerToken != "" {
		t.Error("a cached context arrived carrying a bearer token")
	}
	if len(second.TenantIDs()) != 2 {
		t.Errorf("second request scope = %v, want both tenants", second.TenantIDs())
	}
}

// A failure is never cached. Caching one is how a restored membership fails
// to take effect, or an outage outlives itself.
func TestFailuresAreNotCached(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(meContextBody{PersonID: "p1"})
	}))
	t.Cleanup(server.Close)
	client := NewDexIDClientWith(server.URL, "app", DexIDOptions{})

	for i := 0; i < 2; i++ {
		if _, err := client.FetchContext(context.Background(), "tok"); err == nil {
			t.Fatal("an upstream 500 was not reported as an error")
		}
	}
	access, err := client.FetchContext(context.Background(), "tok")
	if err != nil {
		t.Fatalf("the third attempt failed: %v — a failure was cached", err)
	}
	if access.PersonID != "p1" {
		t.Errorf("PersonID = %q, want p1", access.PersonID)
	}
}

// A negative TTL disables caching outright, for a deployment that would rather
// pay the hop than tolerate any staleness.
func TestCachingCanBeDisabled(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{PersonID: "p1"})
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{ContextTTL: -1})

	for i := 0; i < 3; i++ {
		if _, err := client.FetchContext(context.Background(), "tok"); err != nil {
			t.Fatal(err)
		}
	}
	if got := dexid.callCount(); got != 3 {
		t.Errorf("identity plane called %d times with caching disabled, want 3", got)
	}
}

func TestTheCacheIsSafeUnderConcurrentUse(t *testing.T) {
	dexid := newFakeDexID(t, meContextBody{
		PersonID: "p1",
		Tenants:  []TenantMembership{member("alpha", "member")},
	})
	client := NewDexIDClientWith(dexid.server.URL, "app", DexIDOptions{})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.FetchContext(context.Background(), "tok"); err != nil {
				t.Errorf("FetchContext: %v", err)
			}
		}()
	}
	wg.Wait()
}
