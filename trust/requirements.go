package trust

import "fmt"

// ─── entitlements ────────────────────────────────────────────────────────

type featureRequirement struct {
	key string
	// provisionalAllow permits the act when the tenant has NO entitlement
	// data at all — see RequireFeatureWhenProvisioned.
	provisionalAllow bool
}

func (f featureRequirement) label() string { return f.key }

func (f featureRequirement) satisfiedBy(a *Access, tenantID string) bool {
	if a.HasEntitlement(tenantID, f.key) {
		return true
	}
	return f.provisionalAllow && !a.EntitlementsProvisioned(tenantID)
}

func (f featureRequirement) deniedReason() string { return ReasonTenantNotEntitled }

func (f featureRequirement) deniedExplanation() string {
	return "this organisation's plan does not include " + f.key
}

func (f featureRequirement) deniedRemediation() string {
	return "ask an administrator to add this capability to the organisation's plan"
}

// RequireFeature demands that the tenant hold featureKey.
//
// FAILS CLOSED in every direction: a tenant with no entitlement rows is not
// entitled, an unreachable identity plane never reaches this check (the Gate
// has already refused with context_unavailable), and a caller with no
// memberships is refused before a feature is even considered.
//
// Use this once the feature's entitlement data actually exists. Until it does,
// see RequireFeatureWhenProvisioned.
func RequireFeature(featureKey string) Requirement {
	return featureRequirement{key: featureKey}
}

// RequireFeatureWhenProvisioned demands featureKey ONLY of tenants that have
// entitlement data — a tenant with an empty entitlement set is allowed
// through.
//
// This is the honest way to land enforcement ahead of the data it enforces
// against. The entitlement table is populated per tenant by plan assignment;
// until a plan is assigned, every tenant looks exactly like a tenant that was
// denied everything, and RequireFeature would take the whole product offline
// for its own authors on the day it shipped.
//
// The distinction is not a permanent mode. It is load-bearing in one
// direction only: the moment a tenant is given ANY entitlement, this
// requirement becomes indistinguishable from RequireFeature FOR THAT TENANT,
// with no code change and no deploy. So enforcement arrives with the data,
// tenant by tenant, which is also exactly what the wave's verification asks
// for — flip a plan, see the API's answer change within the context TTL.
//
// Swap the call site to RequireFeature once every tenant is provisioned; the
// difference is then nil, and removing the escape hatch is the point.
func RequireFeatureWhenProvisioned(featureKey string) Requirement {
	return featureRequirement{key: featureKey, provisionalAllow: true}
}

// ─── roles ───────────────────────────────────────────────────────────────

// RoleSet names the roles that satisfy a role requirement, across the two
// axes DexID reports. Holding ANY ONE of them is enough.
//
// The two axes are not interchangeable, and choosing between them is the
// single most consequential decision in writing a role gate:
//
//   - Tenant roles are tenant_membership.role. They REACH AGENTS: DexID copies
//     a person's memberships onto every agent they enroll and carries later
//     changes across, so granting a human 'admin' in a tenant grants their
//     assistants the same standing on the next call.
//   - Platform roles are person-level grants. They DO NOT reach agents — an
//     agent's platform_roles are read from its own person row, which is never
//     granted anything. A gate written on platform roles alone refuses every
//     agent, including the ones the platform's own automation runs on.
//
// So: put the everyday authority on the tenant axis, and use the platform axis
// for break-glass human administration.
type RoleSet struct {
	// Tenant roles, matched against the caller's membership role in the
	// tenant being judged.
	Tenant []string
	// Platform roles, matched against the caller's person-level roles.
	Platform []string
}

type roleRequirement struct {
	name  string
	roles RoleSet
}

func (r roleRequirement) label() string { return r.name }

func (r roleRequirement) satisfiedBy(a *Access, tenantID string) bool {
	for _, want := range r.roles.Platform {
		for _, held := range a.PlatformRoles {
			if held == want {
				return true
			}
		}
	}
	if m, ok := a.Membership(tenantID); ok {
		for _, want := range r.roles.Tenant {
			if m.Role == want {
				return true
			}
		}
	}
	return false
}

func (r roleRequirement) deniedReason() string { return ReasonRoleDenied }

func (r roleRequirement) deniedExplanation() string {
	return fmt.Sprintf("this action requires the %s role", r.name)
}

func (r roleRequirement) deniedRemediation() string {
	return "ask an administrator of this organisation to grant you the role"
}

// RequireRole demands that the caller hold one of the named roles in the
// tenant being judged. name appears in refusals and logs, so give it the
// vocabulary a person would use ("administrator"), not the implementation's.
//
// An EMPTY RoleSet satisfies nobody. That is deliberate: a role gate
// misconfigured to name no roles must refuse everything loudly rather than
// admit everyone silently.
func RequireRole(name string, roles RoleSet) Requirement {
	return roleRequirement{name: name, roles: roles}
}
