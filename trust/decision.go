package trust

import (
	"net/http"
	"time"
)

// Decision is the structured result of one check — never a bare boolean, so
// a log, a response body and a test can all say WHY.
//
// Shaped to match the Dart FeatureDecision a client renders, so a refusal can
// travel from here to a screen without being translated on the way.
type Decision struct {
	// Requirement names what was checked: a feature key for an entitlement
	// check, a role-set label for a role check.
	Requirement string `json:"requirement"`
	// Status is the outcome class.
	Status DecisionStatus `json:"status"`
	// ReasonCode is the stable machine-readable cause. See reason.go.
	ReasonCode string `json:"reasonCode"`
	// Explanation is human-safe: it says what is missing without naming
	// tenants the caller cannot already see.
	Explanation string `json:"explanation"`
	// Source is which evaluator produced this. Always "backend.trust" here —
	// the value exists so a client can tell a server decision from its own.
	Source string `json:"source"`
	// TenantID is the tenant the decision was evaluated against, when one
	// could be resolved.
	TenantID string `json:"tenantId,omitempty"`
	// Remediation is the caller's next step, when there is an actionable one.
	Remediation string `json:"remediation,omitempty"`
	// EvaluatedAt is when this was decided. Decisions are point-in-time; they
	// are not cached authorization.
	EvaluatedAt time.Time `json:"evaluatedAt"`
}

// Allowed reports whether the operation may proceed.
func (d Decision) Allowed() bool { return d.Status == StatusAllowed }

// HTTPStatus is the response status a refusal should carry.
//
// 403 for every denial, deliberately, including the not-a-member case. A 404
// would be the disclosure-safe answer for a check about a NAMED OBJECT, but
// these decisions are about the CALLER's own scope and roles — facts they
// already hold — so there is nothing to leak by answering precisely, and a
// precise answer is what makes the refusal actionable.
func (d Decision) HTTPStatus() int {
	if d.Allowed() {
		return http.StatusOK
	}
	return http.StatusForbidden
}

// Requirement is one condition a route family or a handler imposes.
//
// Implementations live in this package only: a Requirement decides security
// outcomes, and an interface an app could implement is one an app can get
// subtly wrong in its own way — which is the failure mode this whole module
// exists to remove.
type Requirement interface {
	// label names the requirement in a Decision and in logs.
	label() string
	// satisfiedBy answers the requirement for ONE tenant.
	satisfiedBy(a *Access, tenantID string) bool
	// deniedReason is the code to report when no tenant in scope satisfies it.
	deniedReason() string
	// deniedExplanation and deniedRemediation are the human-facing halves.
	deniedExplanation() string
	deniedRemediation() string
}

// Decide evaluates req against the caller, resolving which tenant to judge
// from the REQUEST's scope. See scope.go for the resolution rules.
func Decide(a *Access, req Requirement) Decision {
	return decideAt(a, req, time.Now().UTC())
}

// DecideFor evaluates req against ONE explicitly named tenant — for a handler
// that already knows which tenant the act targets because the request body
// named it, and should not have that re-derived from header scope.
//
// The caller must have checked membership of tenantID first (HasTenant); this
// answers the entitlement/role question, not the membership one, and reports
// tenant_not_licensed if handed a tenant the caller does not belong to.
func DecideFor(a *Access, tenantID string, req Requirement) Decision {
	return decideForAt(a, tenantID, req, time.Now().UTC())
}

func decideForAt(a *Access, tenantID string, req Requirement, now time.Time) Decision {
	if a == nil || !a.HasTenant(tenantID) {
		return denial(req, "", ReasonTenantNotLicensed,
			"this account has no access to the requested organisation",
			"sign in again, or ask an administrator for access", now)
	}
	if req.satisfiedBy(a, tenantID) {
		return allowed(req, tenantID, now)
	}
	return denial(req, tenantID, req.deniedReason(),
		req.deniedExplanation(), req.deniedRemediation(), now)
}

func decideAt(a *Access, req Requirement, now time.Time) Decision {
	scope, refusal := resolveScope(a, req, now)
	if refusal != nil {
		return *refusal
	}

	satisfied, unsatisfied := 0, 0
	firstSatisfied := ""
	for _, tenantID := range scope {
		if req.satisfiedBy(a, tenantID) {
			satisfied++
			if firstSatisfied == "" {
				firstSatisfied = tenantID
			}
		} else {
			unsatisfied++
		}
	}

	switch {
	case unsatisfied == 0:
		// Satisfied everywhere the request could possibly be acting. Report
		// the concrete tenant when the scope was one, and leave it blank when
		// the answer holds across several — naming one would be arbitrary.
		if len(scope) == 1 {
			return allowed(req, scope[0], now)
		}
		return allowed(req, "", now)
	case satisfied == 0:
		return denial(req, singleOrEmpty(scope), req.deniedReason(),
			req.deniedExplanation(), req.deniedRemediation(), now)
	default:
		// MIXED. The caller could act here in one organisation and not in
		// another, and an all-tenants request does not say which one it means.
		// Answering yes would grant the permissive tenant's answer to the
		// restrictive one; answering no would be wrong and unexplainable.
		// Asking them to narrow is the only correct answer, and it is exactly
		// what focus_required means in the client engine.
		return denial(req, "", ReasonFocusRequired,
			"this action is allowed in some of your organisations but not others",
			"choose a single organisation and try again", now)
	}
}

func singleOrEmpty(scope []string) string {
	if len(scope) == 1 {
		return scope[0]
	}
	return ""
}

func allowed(req Requirement, tenantID string, now time.Time) Decision {
	return Decision{
		Requirement: req.label(),
		Status:      StatusAllowed,
		ReasonCode:  ReasonAllowed,
		Explanation: "allowed",
		Source:      DecisionSource,
		TenantID:    tenantID,
		EvaluatedAt: now,
	}
}

func denial(req Requirement, tenantID, reason, explanation, remediation string, now time.Time) Decision {
	return Decision{
		Requirement: req.label(),
		Status:      StatusDenied,
		ReasonCode:  reason,
		Explanation: explanation,
		Source:      DecisionSource,
		TenantID:    tenantID,
		Remediation: remediation,
		EvaluatedAt: now,
	}
}

// DecisionSource is the Decision.Source value every decision from this module
// carries, so a client can tell a backend decision from its own local one.
const DecisionSource = "backend.trust"
