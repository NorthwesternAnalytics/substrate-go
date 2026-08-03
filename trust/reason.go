package trust

// Reason codes and decision statuses, kept in lockstep with the Dart client
// engine in substrate_contract (lib/src/feature/feature_decision.dart).
//
// THE STRINGS ARE THE CONTRACT. A client that refuses an action locally and a
// backend that refuses the same action must name the same cause, or a support
// question ("why can't I do this?") gets two different answers depending on
// which layer happened to answer first. reason_parity_test.go asserts this
// file against the Dart source rather than trusting that the two were kept in
// step by hand.
//
// NEVER RENAME A RELEASED CODE. Add a new one instead; something is logging,
// asserting on, or displaying the old one.

// DecisionStatus is the outcome class of a check, mirroring Dart's
// FeatureDecisionStatus.
type DecisionStatus string

const (
	// StatusAllowed — the operation may proceed.
	StatusAllowed DecisionStatus = "allowed"
	// StatusDenied — authorization-style denial (role, entitlement, object
	// tenant).
	StatusDenied DecisionStatus = "denied"
	// StatusHidden — the feature should not be presented at all.
	StatusHidden DecisionStatus = "hidden"
	// StatusDisabled — present but not currently usable.
	StatusDisabled DecisionStatus = "disabled"
	// StatusDegraded — usable with reduced functionality.
	StatusDegraded DecisionStatus = "degraded"
)

// Stable reason codes. Each names the pipeline step that produced the
// decision.
const (
	// ReasonAllowed — allowed by the full pipeline.
	ReasonAllowed = "allowed"
	// ReasonNotCompiled — feature key is not compiled into this product.
	ReasonNotCompiled = "not_compiled"
	// ReasonModuleNotInstalled — owning module is not installed by the
	// product manifest.
	ReasonModuleNotInstalled = "module_not_installed"
	// ReasonEnvironmentDisabled — environment configuration disables the
	// feature.
	ReasonEnvironmentDisabled = "environment_disabled"
	// ReasonKilled — remote rollout/kill switch disables the feature.
	ReasonKilled = "kill_switch"
	// ReasonTenantNotLicensed — tenant is not licensed for the app. On the
	// backend this is also what a caller scoped to a tenant they are not a
	// member of receives, since DexID returns licensed memberships only and
	// the two are indistinguishable from here.
	ReasonTenantNotLicensed = "tenant_not_licensed"
	// ReasonTenantNotEntitled — tenant lacks the entitlement for this feature.
	ReasonTenantNotEntitled = "tenant_not_entitled"
	// ReasonRoleDenied — the person's role does not permit the operation.
	ReasonRoleDenied = "role_denied"
	// ReasonFocusRequired — operation requires single-tenant focus but scope
	// is all-tenants.
	ReasonFocusRequired = "focus_required"
	// ReasonObjectTenantNotEntitled — target object's owning tenant is not
	// entitled to the feature (ADR-004 object restriction).
	ReasonObjectTenantNotEntitled = "object_tenant_not_entitled"
	// ReasonDependencyUnhealthy — a declared feature dependency is unhealthy.
	ReasonDependencyUnhealthy = "dependency_unhealthy"
	// ReasonDependencyDenied — a declared feature dependency was itself not
	// allowed.
	ReasonDependencyDenied = "dependency_denied"
	// ReasonUnknownFeature — the feature key is not registered at all.
	ReasonUnknownFeature = "unknown_feature"
)

// ReasonCodes is every code this package knows, in the order the Dart file
// declares them. The parity test walks it.
var ReasonCodes = []string{
	ReasonAllowed,
	ReasonNotCompiled,
	ReasonModuleNotInstalled,
	ReasonEnvironmentDisabled,
	ReasonKilled,
	ReasonTenantNotLicensed,
	ReasonTenantNotEntitled,
	ReasonRoleDenied,
	ReasonFocusRequired,
	ReasonObjectTenantNotEntitled,
	ReasonDependencyUnhealthy,
	ReasonDependencyDenied,
	ReasonUnknownFeature,
}

// DecisionStatuses is every status this package knows, matching Dart's enum.
var DecisionStatuses = []DecisionStatus{
	StatusAllowed,
	StatusDenied,
	StatusHidden,
	StatusDisabled,
	StatusDegraded,
}
