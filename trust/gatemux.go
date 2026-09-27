package trust

import (
	"fmt"
	"net/http"
	"sort"
)

// RouteAccess says which trust boundary a mounted route uses.
type RouteAccess string

const (
	// RouteGated is a route wrapped by Gate.Protect.
	RouteGated RouteAccess = "gated"
	// RoutePublic is a route explicitly declared public when the GateMux was built.
	RoutePublic RouteAccess = "public"
)

// Route is immutable metadata for one mounted route.
//
// GateMux returns Route values rather than its internal maps so callers may
// inspect a server's complete surface without gaining a way to change it.
type Route struct {
	Pattern string
	Access  RouteAccess
}

// GateMux is the only route-registration seam for a substrate API.
//
// Its ServeMux is private: a caller can mount a handler only through Gated or
// Public. Public patterns must be enumerated at construction and every such
// declaration must be mounted before Validate succeeds. This makes an
// accidental ungated route unavailable as a program shape rather than a fact
// a later review has to notice.
type GateMux struct {
	gate           *Gate
	mux            *http.ServeMux
	declaredPublic map[string]struct{}
	mounted        map[string]RouteAccess
}

// NewGateMux builds a gate-only router with an explicit public-route list.
func NewGateMux(gate *Gate, publicPatterns ...string) *GateMux {
	m := &GateMux{
		gate:           gate,
		mux:            http.NewServeMux(),
		declaredPublic: make(map[string]struct{}, len(publicPatterns)),
		mounted:        make(map[string]RouteAccess),
	}
	for _, pattern := range publicPatterns {
		if pattern == "" {
			panic("trust: GateMux public pattern is empty")
		}
		if _, exists := m.declaredPublic[pattern]; exists {
			panic("trust: GateMux public pattern declared twice: " + pattern)
		}
		m.declaredPublic[pattern] = struct{}{}
	}
	return m
}

// Gated mounts next behind the full trust Gate.
func (m *GateMux) Gated(pattern string, next http.Handler, reqs ...Requirement) {
	if m.gate == nil {
		panic("trust: GateMux cannot mount a gated route without a Gate")
	}
	m.claim(pattern, RouteGated)
	m.mux.Handle(pattern, m.gate.Protect(next.ServeHTTP, reqs...))
}

// Public mounts next only when pattern was declared public at construction.
func (m *GateMux) Public(pattern string, next http.Handler) {
	if _, allowed := m.declaredPublic[pattern]; !allowed {
		panic("trust: GateMux refused undeclared public route: " + pattern)
	}
	m.claim(pattern, RoutePublic)
	m.mux.Handle(pattern, next)
}

func (m *GateMux) claim(pattern string, access RouteAccess) {
	if pattern == "" {
		panic("trust: GateMux route pattern is empty")
	}
	if existing, mounted := m.mounted[pattern]; mounted {
		panic(fmt.Sprintf("trust: GateMux route %s already mounted as %s", pattern, existing))
	}
	m.mounted[pattern] = access
}

// Validate refuses an incomplete public-route declaration.
func (m *GateMux) Validate() error {
	for pattern := range m.declaredPublic {
		if m.mounted[pattern] != RoutePublic {
			return fmt.Errorf("trust: GateMux declared public route %s was not mounted", pattern)
		}
	}
	return nil
}

// Routes returns a deterministic copy of the mounted-route inventory.
func (m *GateMux) Routes() []Route {
	routes := make([]Route, 0, len(m.mounted))
	for pattern, access := range m.mounted {
		routes = append(routes, Route{Pattern: pattern, Access: access})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Pattern < routes[j].Pattern })
	return routes
}

// ServeHTTP dispatches only routes admitted through Gated or Public.
func (m *GateMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mux.ServeHTTP(w, r)
}
