// Package trust is the substrate's shared security middleware: the code every
// Go backend in the platform needs before it may look at a single row.
//
// It answers four questions, in this order, and refuses at the first one that
// fails:
//
//  1. Is this token real?           — Supabase JWT validation against the
//     project's published JWKS (validator.go).
//  2. Who is the caller, and what
//     may they reach?               — the DexID access context: tenant
//     memberships, per-tenant entitlements, platform roles, and the ownership
//     family an agent belongs to (dexid.go, access.go).
//  3. What is this REQUEST scoped
//     to?                           — X-Tenant-Focus narrowing, applied once,
//     at the seam (access.go).
//  4. May they do THIS?             — role and entitlement decisions per route
//     family, failing closed, carrying the same reason codes the Dart client
//     engine uses (decision.go, gate.go).
//
// # Why this exists
//
// Steps 1 to 3 were hand-copied into every substrate Go backend. PortfoliDEX's
// internal/authn said so in its own package comment — "duplicated rather than
// shared, since every substrate product app owns its whole stack" — and that
// copy had itself been taken from nwa.bundle.platform.oauth's dexid service,
// then copied again into nwa.substrate.poc.projectmanagement. Three copies of a
// security control is three places a fix has to be remembered, and the tenant-
// focus narrowing landed in exactly one of them.
//
// Step 4 never existed anywhere. Every backend enforced tenant isolation and
// stopped: inside a tenant, any member could do anything, including delete.
// Adding it here rather than in one app is the point — substrate manages
// security and trust, rather than hoping each app remembers to.
//
// # How an app adopts it
//
// Build a Gate once at startup, enumerate the deliberately public surface,
// and register every route through GateMux:
//
//	gate := trust.NewGate(trust.GateConfig{
//		Validator:  trust.NewValidator(jwksURL, issuer),
//		DexID:      trust.NewDexIDClient(dexidBaseURL, appID),
//		RequireMFA: true,
//		Refuse:     myApp.writeRefusal, // keep your own error envelope
//	})
//
//	mux := trust.NewGateMux(gate, "GET /health", "OPTIONS /")
//	mux.Public("GET /health", health)
//	mux.Public("OPTIONS /", preflight)
//	mux.Gated("GET /v1/things", things.List)
//	mux.Gated("DELETE /v1/things/{id}", things.Delete, adminOnly)
//	if err := mux.Validate(); err != nil {
//		return err
//	}
//
// Handlers then read the caller with trust.FromContext(r.Context()) and scope
// their queries with access.TenantIDs(). A handler that needs a decision the
// route table cannot express — because it depends on the request body — calls
// trust.DecideFor directly with the tenant the body named.
//
// GateMux keeps its underlying http.ServeMux private. The only registration
// verbs are Gated and Public; Public refuses any pattern not enumerated by the
// constructor, and Routes returns immutable metadata for an adopting API's
// build-time conformance walk.
//
// # Where this module lives
//
// In the PortfoliDEX repository, at libs/substrate-go, imported by
// services/api through a `replace` directive. It is a real, separate Go module
// with its own go.mod: nothing about it is PortfoliDEX-specific, and it does
// not import anything from the PortfoliDEX module.
//
// It is here rather than in github.com/dextech-dev/substrate-go because a new
// remote repository is a coordination step that would have blocked the whole
// wave, and because the first importer needs to prove the API is right before
// other backends are asked to depend on it. Graduating it later is small and
// mechanical:
//
//   - move libs/substrate-go/ to the root of a new repository — the module
//     path github.com/dextech-dev/substrate-go is already correct, so no import in
//     any consuming app changes;
//   - tag it (v0.1.0);
//   - in each consumer's go.mod, replace the `replace` directive with a
//     version in `require`.
//
// The one thing that must NOT happen in the meantime is a consumer importing
// this package by relative path or vendoring it — both would silently recreate
// the copy-paste problem this module exists to end.
package trust
