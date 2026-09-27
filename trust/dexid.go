package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DexIDClient fetches tenant/entitlement/role context from the identity
// plane, forwarding the caller's own (already-validated) Supabase token as
// Bearer — DexID independently validates it via the same JWKS and resolves it
// to a DexID person, their tenant memberships, those tenants' entitlements,
// and their platform roles, for one specific app_id.
type DexIDClient struct {
	baseURL string
	appID   string
	http    *http.Client
	cache   *contextCache
}

// DexIDOptions tunes a client. The zero value is the recommended
// configuration.
type DexIDOptions struct {
	// HTTPClient overrides the default 10s-timeout client.
	HTTPClient *http.Client
	// ContextTTL is how long a fetched context is reused. Zero selects
	// DefaultContextTTL; negative disables caching entirely.
	ContextTTL time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// DefaultContextTTL is how long a caller's DexID context is reused before it
// is fetched again.
//
// This is the knob that trades identity-plane load against how stale an
// authorization decision may be, and thirty seconds is chosen from both ends:
//
//   - Without a cache, every request to every backend is a second network hop
//     into DexID, and a route that fans out into several sub-requests
//     multiplies it. The context is identical across all of them.
//   - With too long a TTL, access REVOKED in Support Center keeps working.
//     DexID deliberately derives an agent's tenants from its owner live, "so
//     access the owner loses, the agent loses on its very next call"; a long
//     TTL here would quietly undo that guarantee for every app that adopts
//     this module.
//
// Thirty seconds keeps revocation inside a minute and still collapses a burst
// of requests from one screen into one identity-plane call. It is also the
// window the wave's own verification measures against: flip a plan, and the
// API's answer must change within the TTL.
const DefaultContextTTL = 30 * time.Second

// NewDexIDClient creates a client against baseURL for appID, with the default
// context cache.
func NewDexIDClient(baseURL, appID string) *DexIDClient {
	return NewDexIDClientWith(baseURL, appID, DexIDOptions{})
}

// NewDexIDClientWith creates a client with explicit options.
func NewDexIDClientWith(baseURL, appID string, opts DexIDOptions) *DexIDClient {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	ttl := opts.ContextTTL
	if ttl == 0 {
		ttl = DefaultContextTTL
	}
	return &DexIDClient{
		baseURL: baseURL,
		appID:   appID,
		http:    httpClient,
		cache:   newContextCache(ttl, opts.Now),
	}
}

// meContextBody is DexID's /v1/me/context response.
//
// Every field DexID sends is decoded here. The copies this was extracted from
// dropped `entitlements` and `platform_roles` on the floor — which is the
// mechanical reason no substrate backend could enforce a feature key or a
// role, however much the design documents said they should.
type meContextBody struct {
	PersonID      string             `json:"person_id"`
	DisplayName   string             `json:"display_name"`
	Tenants       []TenantMembership `json:"tenants"`
	PlatformRoles []string           `json:"platform_roles"`
	IsAgent       bool               `json:"is_agent"`
	OwnerPersonID string             `json:"owner_person_id"`
	PrincipalIDs  []string           `json:"principal_ids"`
}

// FetchContext resolves the caller's DexID access context for this app,
// serving it from the TTL cache when a recent one is held for the same token.
//
// The returned *Access is always a fresh copy the caller may mutate (the Gate
// stamps BearerToken and tenant focus onto it); the cached value is never
// handed out directly.
func (c *DexIDClient) FetchContext(ctx context.Context, bearerToken string) (*Access, error) {
	if cached, ok := c.cache.get(bearerToken); ok {
		return cached, nil
	}

	endpoint := fmt.Sprintf("%s/v1/me/context?app_id=%s", c.baseURL, url.QueryEscape(c.appID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dexid unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dexid context status %d", resp.StatusCode)
	}

	var body meContextBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("dexid context malformed: %w", err)
	}

	// NOTHING IS CACHED ON A FAILURE PATH. A refusal or an outage must be
	// re-asked on the next request, never remembered: caching a denial is how
	// a restored membership fails to take effect.
	access := accessFromContextBody(body)
	c.cache.put(bearerToken, access)
	return &access, nil
}

// accessFromContextBody is the ONE translation from DexID's context document into
// an Access.
//
// EXTRACTED BECAUSE TWO DOORS NOW REACH THE SAME DOCUMENT (nw#4424): a person's
// own /v1/me/context, and the service route a gate-authenticated request needs.
// Two translations would be two readings of one document, and a field added to the
// document would reach whichever of them somebody remembered.
func accessFromContextBody(body meContextBody) Access {
	return Access{
		PersonID:      body.PersonID,
		DisplayName:   body.DisplayName,
		Tenants:       body.Tenants,
		PlatformRoles: body.PlatformRoles,
		IsAgent:       body.IsAgent,
		OwnerPersonID: body.OwnerPersonID,
		PrincipalIDs:  body.PrincipalIDs,
	}
}

// CacheStats reports hits and misses since start, for a health endpoint or a
// test that needs to prove the cache is actually being consulted.
func (c *DexIDClient) CacheStats() (hits, misses int) { return c.cache.stats() }

// ResolvePersonName looks up personID's display name within tenantID, for
// server-side assignee-name derivation: a person id is a reference to a
// record the identity plane owns, not a row a product service has a local
// table for, so resolving it means asking DexID.
//
// It calls GET /v1/tenants/{tenantId}/roster forwarding bearerToken -- the
// CALLER's own token, not a service credential, because roster access is
// self-service (any member of a tenant can see who else is in it) rather than
// admin-gated. This piggybacks on a token the request already carried rather
// than requiring the app to hold one of its own.
//
// Returns found=false (not an error) when personID is not on that tenant's
// roster -- unknown or inactive, not merely unreachable; the caller turns
// that into a 422 rather than a 500.
func (c *DexIDClient) ResolvePersonName(ctx context.Context, bearerToken, tenantID, personID string) (string, bool, error) {
	if personID == "" {
		return "", false, nil
	}
	endpoint := fmt.Sprintf("%s/v1/tenants/%s/roster", c.baseURL, url.PathEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("dexid unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("dexid roster status %d", resp.StatusCode)
	}

	var body struct {
		People []struct {
			PersonID    string `json:"person_id"`
			DisplayName string `json:"display_name"`
		} `json:"people"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", false, fmt.Errorf("dexid roster malformed: %w", err)
	}
	for _, p := range body.People {
		if p.PersonID == personID {
			return p.DisplayName, true, nil
		}
	}
	return "", false, nil
}
