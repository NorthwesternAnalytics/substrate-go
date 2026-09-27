package trust

import (
	"context"
	"errors"
	"net/http"
)

// AuthKind says how a request was authenticated, so an audit record can
// distinguish the two paths rather than leaving a reader to infer it.
type AuthKind string

const (
	// AuthBearer is the caller's own Supabase access token.
	AuthBearer AuthKind = "bearer"
	// AuthGate is a signed DexID identity assertion arriving through the login
	// wall, on a request that carries no token of its own.
	AuthGate AuthKind = "gate"
)

// GateContextResolver answers "what may this person reach" for a caller who
// presented no token of their own.
//
// WHY THIS IS A SEAM AND NOT A METHOD ON DexIDClient. DexID has exactly one
// context route, GET /v1/me/context, and it is keyed on the CALLER's bearer — a
// gate-authenticated request has none, which is the point of the gate. So a
// service asking about a person it did not receive a token from has no endpoint
// today (nw#4423 seq 16243). The seam is here so the gate path is complete and
// testable now; the endpoint behind it is its own story, because adding a way for
// a service to ask about an arbitrary person changes DexID's API and is a ruling
// rather than an implementation detail.
//
// A resolver MUST derive everything from the identity it is given. Reading
// anything off the request would reintroduce the header trust this whole control
// exists to remove, which is why the request is not a parameter.
type GateContextResolver interface {
	ResolveFor(ctx context.Context, id GateIdentity) (*Access, error)
}

// GateContextResolverFunc adapts a function to GateContextResolver.
type GateContextResolverFunc func(ctx context.Context, id GateIdentity) (*Access, error)

// ResolveFor implements GateContextResolver.
func (f GateContextResolverFunc) ResolveFor(ctx context.Context, id GateIdentity) (*Access, error) {
	return f(ctx, id)
}

// authenticateGate handles a request with no Bearer token but with DexID gate
// headers, returning the caller's Access or writing the refusal itself.
//
// ONE NON-REVEALING REFUSAL FOR EVERY FAILURE. No assertion, a forged one, a
// stale one, a replay, a header that disagrees with the signature: all of them
// are "sign in required" with CodeNotAuthenticated, and the reason goes to the
// log. Which one it was tells an attacker how far they got and helps a legitimate
// caller not at all — their request either carries a fresh assertion from DexID
// or it does not.
//
// The second return value reports whether the request was handled here; false
// means the caller should carry on with its own refusal.
func (g *Gate) authenticateGate(w http.ResponseWriter, r *http.Request) (*Access, bool) {
	// NOT CONFIGURED MEANS NOT TRUSTED, and it must not even look like an
	// attempt: a deployment with no verifier behaves exactly as it did before
	// this story, so gate headers are ignored and the ordinary "no Bearer"
	// refusal stands (nw#4423 item 4).
	if g.assertions == nil {
		return nil, false
	}
	if !HasGateHeaders(r) {
		return nil, false
	}

	id, err := g.assertions.Verify(r.Context(), r)
	if err != nil {
		// Debug for the ordinary case, warn for a forgery: a request with
		// identity headers and no assertion is what an unconfigured proxy or a
		// probe produces, while a PRESENT assertion that fails verification is
		// somebody trying something.
		if errors.Is(err, ErrNoAssertion) {
			g.log.Debug("gate identity presented without an assertion",
				"method", r.Method, "path", r.URL.Path)
		} else {
			g.log.Warn("gate assertion rejected", "error", err,
				"method", r.Method, "path", r.URL.Path)
		}
		g.refuse(w, r, Refusal{
			Status: http.StatusUnauthorized, Code: CodeNotAuthenticated,
			Message: "sign in required",
		})
		return nil, true
	}

	// FAIL CLOSED WITH NO RESOLVER. The assertion is valid and this service
	// cannot establish what the person may reach, so it must not admit them —
	// authenticating someone it cannot scope is how a tenant boundary is crossed.
	if g.gateContext == nil {
		g.log.Error("gate assertion verified but no GateContextResolver is configured; refusing",
			"person_id", id.PersonID, "kid", id.KeyID)
		g.refuse(w, r, Refusal{
			Status: http.StatusServiceUnavailable, Code: CodeContextUnavailable,
			Message: "tenant context is temporarily unavailable",
		})
		return nil, true
	}

	access, err := g.gateContext.ResolveFor(r.Context(), *id)
	switch {
	case errors.Is(err, ErrGateContextRefused):
		// A REFUSAL IS NOT AN OUTAGE (found by nw#4438's end-to-end test). The
		// identity plane answered, and its answer is "not for this app" — an
		// unknown principal, a revoked key, or a person in no tenant this app
		// serves. 503 would tell the caller to retry something that will never
		// succeed and would read as an incident in every dashboard; the honest
		// answer is the same non-revealing 401 every other gate failure gets, so a
		// caller learns only that it is not signed in here.
		g.log.Warn("gate context refused", "person_id", id.PersonID, "kid", id.KeyID)
		g.refuse(w, r, Refusal{
			Status: http.StatusUnauthorized, Code: CodeNotAuthenticated,
			Message: "sign in required",
		})
		return nil, true
	case err != nil:
		// Anything else IS an outage: unreachable, malformed, a bad status. The
		// caller did nothing wrong and retrying is the right advice.
		g.log.Warn("gate context unavailable", "error", err, "person_id", id.PersonID)
		g.refuse(w, r, Refusal{
			Status: http.StatusServiceUnavailable, Code: CodeContextUnavailable,
			Message: "tenant context is temporarily unavailable",
		})
		return nil, true
	}
	if access == nil {
		g.log.Error("gate context resolver returned no access and no error", "person_id", id.PersonID)
		g.refuse(w, r, Refusal{
			Status: http.StatusServiceUnavailable, Code: CodeContextUnavailable,
			Message: "tenant context is temporarily unavailable",
		})
		return nil, true
	}

	// THE SIGNED CLAIMS WIN over whatever the resolver reported about identity.
	// A resolver keyed on the person id cannot disagree about who they are, and
	// if it ever did, the signature is the thing DexID vouched for.
	access.PersonID = id.PersonID
	access.AuthKind = AuthGate
	access.VerifyClass = id.VerifyClass
	access.AssertionKeyID = id.KeyID
	if id.AAL != "" {
		access.AAL = id.AAL
	}

	// NO BEARER TOKEN, deliberately. Access.BearerToken exists so a handler can
	// make a second identity-plane call AS THE CALLER; there is no such token
	// here, and leaving a stale or borrowed one would let a handler act with
	// credentials that are not the caller's.
	access.BearerToken = ""
	return access, true
}
