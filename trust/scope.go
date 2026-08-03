package trust

import "time"

// Which tenant is a route-level requirement judged against?
//
// A feature key is entitled to a TENANT and a role is held WITHIN a tenant, so
// every requirement needs one before it can be answered — but an HTTP request
// does not always name one. The rules, in order:
//
//  1. No memberships at all → tenant_not_licensed. Nothing to judge against,
//     and no request from such a caller can be acting on anyone's data.
//  2. A focus header naming a tenant the caller belongs to → that tenant,
//     alone. This is the ordinary case: the shell sets X-Tenant-Focus on every
//     request the app makes.
//  3. A focus header naming a tenant the caller does NOT belong to →
//     tenant_not_licensed. Note the asymmetry with TenantIDs(), which answers
//     the same situation with an empty READ scope rather than a refusal: a read
//     returning nothing confirms nothing about whether that tenant exists,
//     whereas an ACT has to be answered one way or the other, and the caller
//     already knows what they asked for.
//  4. No focus → every tenant the caller belongs to, judged universally: the
//     requirement must hold in ALL of them.
//
// Rule 4 is the one worth defending. An unfocused request has not said which
// organisation it means, so the honest reading is "any of them" — and a
// permission that holds in only one of them cannot be assumed to be the one
// intended. Requiring it everywhere is the conservative reading, degenerates
// exactly to rule 2 for the single-tenant caller (which is most of them), and
// answers the mixed case with focus_required, which is actionable. The
// alternative — allow if ANY tenant permits — would let a caller who is admin
// of their own sandbox delete records in an organisation where they are a
// plain member, which is the very gap this module was extracted to close.
func resolveScope(a *Access, req Requirement, now time.Time) (scope []string, refusal *Decision) {
	if a == nil || len(a.Tenants) == 0 {
		d := denial(req, "", ReasonTenantNotLicensed,
			"this account has no access to any organisation for this app",
			"ask an administrator for access", now)
		return nil, &d
	}

	if focus := a.TenantFocus(); focus != "" {
		if a.HasTenant(focus) {
			return []string{focus}, nil
		}
		d := denial(req, "", ReasonTenantNotLicensed,
			"this account has no access to the organisation this request is scoped to",
			"switch to an organisation you belong to", now)
		return nil, &d
	}

	return a.AuthorizedTenantIDs(), nil
}
