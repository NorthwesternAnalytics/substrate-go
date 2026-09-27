package trust

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type ctxKey int

const ctxAccess ctxKey = iota

// NewContext returns a context carrying access, retrievable by FromContext.
func NewContext(ctx context.Context, access *Access) context.Context {
	return context.WithValue(ctx, ctxAccess, access)
}

// FromContext returns the access context the Gate stashed, or nil if none is
// present (a handler reached outside the Gate).
func FromContext(ctx context.Context) *Access {
	access, _ := ctx.Value(ctxAccess).(*Access)
	return access
}

// TenantFocusHeader is the shell's tenant-focus contract, server side.
//
// Set by the client's focus-aware HTTP client on every request the app makes.
// The value is a raw tenant id; ABSENCE means all-tenants, and there is
// deliberately no sentinel value for that — which is what lets a client half
// deploy ahead of a server half, since an all-tenants request is byte-
// identical to what shipped before.
const TenantFocusHeader = "X-Tenant-Focus"

// BlankFocusSentinel is what a present-but-blank header becomes: a value no
// tenant id can equal, so the ordinary intersection yields nothing and the
// fail-closed reading needs no branch of its own downstream.
const BlankFocusSentinel = "\x00blank-tenant-focus"

// ReadTenantFocus extracts the focus from a request.
//
// A PRESENT-BUT-BLANK HEADER FAILS CLOSED — it narrows to nothing rather than
// being read as absence, and this is the one judgement call in the contract.
// A stripped or mangled value could mean either, and the two failure modes are
// not symmetric: read as absence, a blank header silently restores all-tenants
// scope, which is EXACTLY the bug this control exists to eliminate and would
// be invisible in a log. Read as a focus on nothing, it empties every screen —
// alarming, immediate, and reported within a minute. Between a silent widening
// and a loud narrowing, the loud one is always the right default.
//
// Trimmed, because a proxy that pads the value must not turn a member tenant
// into a non-member one.
func ReadTenantFocus(r *http.Request) string {
	values, present := r.Header[http.CanonicalHeaderKey(TenantFocusHeader)]
	if !present || len(values) == 0 {
		return "" // absent: all tenants
	}
	focus := strings.TrimSpace(values[0])
	if focus == "" {
		return BlankFocusSentinel
	}
	return focus
}

// Refusal is everything an app needs to render a denial in its own error
// envelope.
type Refusal struct {
	// Status is the HTTP status to answer with.
	Status int
	// Code is the machine-readable code for the error body. For an
	// authentication-stage refusal it is one of the Code* constants below;
	// for a decision it is the Decision's ReasonCode, so the code a client
	// reads off an API error is the SAME STRING its own feature engine would
	// have produced locally.
	Code string
	// Message is safe to show a person.
	Message string
	// Decision is set for role/entitlement refusals and nil for
	// authentication-stage ones.
	Decision *Decision
}

// Authentication-stage refusal codes.
const (
	// CodeNotAuthenticated — no Bearer token was presented.
	CodeNotAuthenticated = "not_authenticated"
	// CodeTokenInvalid — the token failed validation.
	CodeTokenInvalid = "token_invalid"
	// CodeMFARequired — a session token without the required assurance level.
	CodeMFARequired = "mfa_step_up_required"
	// CodeContextUnavailable — the identity plane could not be reached, so
	// nothing about the caller is known. Fails closed, and 503 rather than
	// 403: the caller did nothing wrong and retrying is the right advice.
	CodeContextUnavailable = "context_unavailable"
)

// RefusalWriter renders a Refusal. An app supplies its own so refusals match
// the error envelope the rest of its API already uses.
type RefusalWriter func(http.ResponseWriter, *http.Request, Refusal)

// GateConfig wires a Gate.
type GateConfig struct {
	// Validator verifies incoming tokens. Required.
	Validator *Validator
	// DexID resolves the caller's access context. Required.
	DexID *DexIDClient
	// RequireMFA rejects session tokens that are not aal2. Delegated OAuth
	// tokens are exempt — see the Gate's MFA comment.
	RequireMFA bool
	// Refuse renders refusals. Defaults to a plain
	// {"error":{"code","message"}} body with the decision attached.
	Refuse RefusalWriter
	// Logger receives one warning per refused decision. Defaults to
	// slog.Default().
	Logger *slog.Logger
	// Observe downgrades ROLE AND ENTITLEMENT refusals to log-and-allow.
	// Authentication, MFA and context failures are never downgraded.
	//
	// It exists so an operator can turn a newly-landed gate off without a
	// deploy when it refuses someone it should not have — the alternative
	// being a rollback of the release that carried it. It is not a
	// configuration to sit in: a gate in observe mode enforces nothing.
	Observe bool
	// Assertions admits DexID GATE IDENTITY: a request with no Bearer token but
	// a valid X-DexID-Assertion authenticates as that person (nw#4423).
	//
	// NIL MEANS GATE HEADERS ARE IGNORED, exactly as before this existed — not
	// trusted, not reported as an attempt, simply not a way in. A deployment that
	// has not turned this on behaves as it did yesterday.
	Assertions *AssertionVerifier

	// GateContext resolves what a gate-authenticated person may reach.
	//
	// REQUIRED WHENEVER Assertions IS SET, and the gate refuses gate identity
	// without it rather than admitting a person it cannot scope. It is a seam
	// because DexID has no service-to-service context route yet — see
	// GateContextResolver (nw#4423 seq 16243).
	GateContext GateContextResolver

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Gate is the composed middleware: authenticate, resolve, narrow, decide.
type Gate struct {
	validator   *Validator
	dexid       *DexIDClient
	requireMFA  bool
	refuse      RefusalWriter
	log         *slog.Logger
	observe     bool
	now         func() time.Time
	assertions  *AssertionVerifier
	gateContext GateContextResolver
}

// NewGate builds a Gate. Build one per process and share it.
func NewGate(cfg GateConfig) *Gate {
	g := &Gate{
		validator:   cfg.Validator,
		dexid:       cfg.DexID,
		requireMFA:  cfg.RequireMFA,
		refuse:      cfg.Refuse,
		log:         cfg.Logger,
		observe:     cfg.Observe,
		now:         cfg.Now,
		assertions:  cfg.Assertions,
		gateContext: cfg.GateContext,
	}
	if g.refuse == nil {
		g.refuse = WriteRefusal
	}
	if g.log == nil {
		g.log = slog.Default()
	}
	if g.now == nil {
		g.now = func() time.Time { return time.Now().UTC() }
	}
	return g
}

// Protect wraps next with the full trust pipeline, and with any additional
// requirements this route family imposes.
//
// The order is not negotiable, and each step depends on the one before it:
//
//	Bearer present → token valid → MFA policy → DexID context → tenant focus
//	→ requirements → handler
//
// Focus is applied AFTER the context, because focus intersects with
// membership and membership has to exist first. Requirements are evaluated
// AFTER focus, because a requirement is judged against the tenant the request
// is scoped to. And every one of them happens before the handler, so a
// handler can never observe an unauthenticated, unscoped or unauthorized
// request.
func (g *Gate) Protect(next http.HandlerFunc, reqs ...Requirement) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			// GATE IDENTITY, only where there is no token of the caller's own
			// (nw#4423). A request carrying BOTH a Bearer and gate headers
			// authenticates by Bearer and the gate headers are ignored: the wall
			// strips them on the native-bearer path anyway, and preferring the
			// weaker of two presented credentials would be the wrong instinct.
			if access, handled := g.authenticateGate(w, r); handled {
				if access == nil {
					return // authenticateGate wrote the refusal
				}
				g.runProtected(w, r, access.WithTenantFocus(ReadTenantFocus(r)), next, reqs)
				return
			}
			g.refuse(w, r, Refusal{
				Status: http.StatusUnauthorized, Code: CodeNotAuthenticated,
				Message: "sign in required",
			})
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")

		claims, err := g.validator.ValidateJWT(r.Context(), token)
		if err != nil {
			// Debug, not warn: a rejected token is the normal consequence of
			// an expired session, and logging it loudly trains people to
			// ignore the log.
			g.log.Debug("token rejected", "error", err)
			g.refuse(w, r, Refusal{
				Status: http.StatusUnauthorized, Code: CodeTokenInvalid,
				Message: "access token rejected",
			})
			return
		}

		// A delegated OAuth token is exempt from the MFA gate, deliberately.
		//
		// AAL describes how a *user session* was authenticated. An OAuth
		// access token is not a session: it is a delegation a person
		// authorized once, through a browser, on a consent screen that
		// requires an MFA-verified session to reach. Supabase mints the grant
		// as a fresh token that does not inherit that session's aal, so
		// requiring aal2 here rejects every MCP client outright -- and no MCP
		// client can perform an MFA step-up, so there is no path forward for
		// it either.
		//
		// The assurance therefore lives at consent time rather than on every
		// call. The residual exposure is real and worth naming: this trusts
		// that reaching the consent screen required MFA.
		if g.requireMFA && !claims.Delegated() && claims.AAL != "aal2" {
			g.refuse(w, r, Refusal{
				Status: http.StatusForbidden, Code: CodeMFARequired,
				Message: "multi-factor authentication is required",
			})
			return
		}

		access, err := g.dexid.FetchContext(r.Context(), token)
		if err != nil {
			g.log.Warn("dexid context unavailable", "error", err)
			g.refuse(w, r, Refusal{
				Status: http.StatusServiceUnavailable, Code: CodeContextUnavailable,
				Message: "tenant context is temporarily unavailable",
			})
			return
		}
		// Stashed so a handler can make a second, self-service identity-plane
		// call on the caller's own behalf without this service holding a
		// service credential -- see Access.BearerToken.
		access.BearerToken = token
		access.AuthKind = AuthBearer
		// The assurance level the Gate just judged, carried so an audit record
		// says what it was rather than only that it passed.
		access.AAL = claims.AAL

		// TENANT FOCUS, APPLIED ONCE, HERE.
		//
		// Being single is the whole value. The bug this closes was not that a
		// screen widened its scope — it was that a screen never narrowed,
		// because narrowing was per-screen discipline and discipline is
		// forgotten on some new screen eventually. Applying focus before the
		// context is handed to any handler means every access.TenantIDs()
		// call site narrows automatically, and there is no longer an omission
		// available to make.
		access = access.WithTenantFocus(ReadTenantFocus(r))

		g.runProtected(w, r, access, next, reqs)
	})
}

// runProtected evaluates this route's requirements against an already
// authenticated, already focused Access and dispatches or refuses.
//
// EXTRACTED SO BOTH AUTHENTICATION PATHS SHARE IT, not for tidiness. Bearer and
// gate identity must be judged by the SAME requirements, in the same order, with
// the same observe-mode behaviour; a second copy of this loop is how the newer
// path quietly ends up skipping a check nobody notices for a year — which is the
// exact failure this package's doc comment was written about.
func (g *Gate) runProtected(w http.ResponseWriter, r *http.Request, access *Access,
	next http.HandlerFunc, reqs []Requirement) {
	for _, req := range reqs {
		decision := decideAt(access, req, g.now())
		if decision.Allowed() {
			continue
		}
		if g.observe {
			g.log.Warn("trust gate would have refused (observe mode)",
				"requirement", decision.Requirement, "reason", decision.ReasonCode,
				"person_id", access.PersonID, "is_agent", access.IsAgent,
				"auth_kind", access.AuthKind,
				"method", r.Method, "path", r.URL.Path)
			continue
		}
		// Warn, not debug: unlike an expired token, a role or
		// entitlement refusal is either a real attempt to exceed
		// authority or a misconfigured grant, and both deserve to be
		// findable in a log without turning debug on.
		g.log.Warn("trust gate refused",
			"requirement", decision.Requirement, "reason", decision.ReasonCode,
			"person_id", access.PersonID, "is_agent", access.IsAgent,
			"auth_kind", access.AuthKind,
			"tenant_id", decision.TenantID,
			"method", r.Method, "path", r.URL.Path)
		g.refuse(w, r, Refusal{
			Status:   decision.HTTPStatus(),
			Code:     decision.ReasonCode,
			Message:  decision.Explanation,
			Decision: &decision,
		})
		return
	}

	next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), access)))
}

// WriteRefusal is the default RefusalWriter: a
// {"error":{"code","message",...}} body, with the decision's reason and
// remediation alongside when there is one.
func WriteRefusal(w http.ResponseWriter, _ *http.Request, refusal Refusal) {
	body := map[string]any{"code": refusal.Code, "message": refusal.Message}
	if refusal.Decision != nil {
		body["reason"] = refusal.Decision.ReasonCode
		body["requirement"] = refusal.Decision.Requirement
		if refusal.Decision.Remediation != "" {
			body["remediation"] = refusal.Decision.Remediation
		}
	}
	writeJSON(w, refusal.Status, map[string]any{"error": body})
}
