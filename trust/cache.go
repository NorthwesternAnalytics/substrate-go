package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// contextCache holds recently fetched DexID contexts for a short TTL.
//
// KEYED BY A HASH OF THE TOKEN, never by the token itself. The key is the
// right one — a bearer token identifies exactly one caller, so two requests
// with the same token are the same caller and may share an answer — but a map
// keyed by raw tokens is a set of live credentials sitting in a long-lived
// process, reachable in a heap dump and easy to log by accident. SHA-256 keeps
// the identity and discards the credential.
//
// The cache is a cache and not a session store: it never extends a token's
// life (an expired token fails validation before this is reached), it holds no
// failures, and losing it entirely costs one extra HTTP call.
type contextCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
	hits    int
	misses  int
}

type cacheEntry struct {
	access    Access
	expiresAt time.Time
}

// maxCacheEntries bounds memory in the pathological case (many distinct
// tokens inside one TTL window — a fleet of agents, or a token refresh storm).
// Reaching it drops the whole map rather than evicting cleverly: at this size
// the cost of being wrong is one extra fetch per caller, and an LRU here would
// be more machinery than the problem deserves.
const maxCacheEntries = 4096

func newContextCache(ttl time.Duration, now func() time.Time) *contextCache {
	if now == nil {
		now = time.Now
	}
	return &contextCache{ttl: ttl, now: now, entries: map[string]cacheEntry{}}
}

func cacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// get returns a COPY of the cached context, so a caller stamping BearerToken
// or tenant focus onto it cannot corrupt what the next request will read.
func (c *contextCache) get(token string) (*Access, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[cacheKey(token)]
	if !ok || !c.now().Before(entry.expiresAt) {
		c.misses++
		return nil, false
	}
	c.hits++
	access := entry.access // struct copy
	return &access, true
}

func (c *contextCache) put(token string, access Access) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= maxCacheEntries {
		c.entries = map[string]cacheEntry{}
	}
	// The focus and the token are per-REQUEST, not per-caller; storing either
	// would hand the next request the previous one's scope.
	access.focusTenantID = ""
	access.BearerToken = ""
	c.entries[cacheKey(token)] = cacheEntry{
		access:    access,
		expiresAt: c.now().Add(c.ttl),
	}
}

func (c *contextCache) stats() (hits, misses int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}
