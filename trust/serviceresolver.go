package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ErrGateContextRefused reports that DexID would not answer about this person for
// this app.
//
// ONE ERROR FOR EVERY REFUSAL, because DexID answers one 404 for all of them —
// unknown principal, revoked key, a person in no tenant this app is licensed for.
// The Gate turns it into its own non-revealing refusal, so nothing downstream can
// accidentally tell a caller which it was.
var ErrGateContextRefused = errors.New("dexid would not answer about that person for this app")

// ServiceContextResolver implements GateContextResolver by asking DexID's
// service-to-service context route (nw#4424), filling the seam nw#4423 left.
//
// WHY A SERVICE CREDENTIAL AND NOT THE CALLER'S. A gate-authenticated request has
// no caller token — that is the point of the login wall. So the app asks as ITSELF,
// with its own service principal, and DexID restricts the answer to tenants where
// that app is licensed and the person is a member. The app's authority is its
// registration, never the shape of its key.
type ServiceContextResolver struct {
	baseURL string
	key     string
	http    *http.Client
}

// ServiceContextOptions tunes the resolver.
type ServiceContextOptions struct {
	// HTTPClient overrides the default 10s-timeout client.
	HTTPClient *http.Client
}

// NewServiceContextResolver builds a resolver.
//
// THE KEY IS A VALUE THE APP SUPPLIES, read from its own operator configuration and
// never from anything this library knows. It is held in memory and sent as a Bearer
// on this one route; it is never logged, never put in an error, and never written to
// any record — a credential that appears in a log is a credential that has leaked.
func NewServiceContextResolver(baseURL, serviceKey string, opts ServiceContextOptions) (*ServiceContextResolver, error) {
	if baseURL == "" {
		return nil, errors.New("service context resolver: baseURL is required")
	}
	if serviceKey == "" {
		return nil, errors.New("service context resolver: a service credential is required; " +
			"without one the gate cannot scope a caller and must refuse")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &ServiceContextResolver{baseURL: baseURL, key: serviceKey, http: client}, nil
}

// ResolveFor asks DexID what the person named by a verified assertion may reach.
func (r *ServiceContextResolver) ResolveFor(ctx context.Context, id GateIdentity) (*Access, error) {
	if id.PersonID == "" {
		return nil, errors.New("service context resolver: no person in the verified assertion")
	}
	// PathEscape, not string concatenation: the person id comes from a SIGNED
	// assertion so it is not attacker-chosen, but a path built by concatenation is
	// a path that becomes injectable the day its source changes.
	endpoint := fmt.Sprintf("%s/v1/context/person/%s", r.baseURL, url.PathEscape(id.PersonID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("service context resolver: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.key)

	resp, err := r.http.Do(req)
	if err != nil {
		// The URL can contain the person id but never the key, since the key is a
		// header. Wrapped as-is because an unreachable identity plane is an outage
		// the Gate reports as one.
		return nil, fmt.Errorf("service context resolver: dexid unreachable: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// EVERY REFUSAL ARRIVES AS THIS, by design on DexID's side, and it stays
		// one thing here.
		return nil, ErrGateContextRefused
	default:
		return nil, fmt.Errorf("service context resolver: dexid context status %d", resp.StatusCode)
	}

	var body meContextBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("service context resolver: dexid context malformed: %w", err)
	}
	// THE SAME TRANSLATION /v1/me/context USES, so one document has one reading.
	access := accessFromContextBody(body)

	// NOT CACHED. DexIDClient caches per bearer token for a TTL, which is right for
	// a caller presenting the same token repeatedly. Here the cache key would be a
	// PERSON, and a gate request is already bounded by a sixty-second assertion —
	// so caching would let a membership change take longer to bite than the
	// credential that carried it, for no saving the assertion's own lifetime does
	// not already give.
	return &access, nil
}
