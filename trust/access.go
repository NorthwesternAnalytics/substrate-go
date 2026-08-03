package trust

// TenantMembership is one tenant this caller may act within for this app, as
// DexID's /v1/me/context describes it.
//
// Entitlements and DisplayName are new here relative to the copies this was
// extracted from: DexID has always returned both, and every copied client
// silently dropped them, which is precisely why no backend could enforce a
// feature key.
type TenantMembership struct {
	TenantID    string `json:"tenant_id"`
	DisplayName string `json:"display_name"`
	// Role is this person's role WITHIN this tenant (tenant_membership.role;
	// 'member' by default). It is the role axis that reaches agents: DexID
	// copies a person's memberships, roles included, onto every agent they
	// run, and carries later changes across too. Platform roles do not
	// propagate that way — see PlatformRoles.
	Role string `json:"role"`
	// Entitlements are the feature keys this tenant holds (tenant_entitlement).
	// An EMPTY slice is meaningful and is not the same as "denied": it means
	// no entitlement data has been provisioned for this tenant yet. See
	// RequireFeatureWhenProvisioned.
	Entitlements []string `json:"entitlements"`
}

// Access is the caller's DexID-sourced access context for one app.
type Access struct {
	PersonID    string
	DisplayName string
	Tenants     []TenantMembership

	// PlatformRoles are the caller's OWN person-level roles
	// ('platform.member' is implied for everyone; 'platform.admin' and
	// friends are granted).
	//
	// KNOWN GAP, and it matters to every role check written against this
	// field: DexID derives an agent's TENANTS from the human who runs it, live,
	// on every request — but it derives platform_roles from the agent's own
	// person row, which is never granted anything. So an agent acting for a
	// platform admin arrives here holding only platform.member. Role gates that
	// depend on platform roles alone therefore refuse every agent. Gate the
	// tenant Role axis instead, which does reach agents, and treat platform
	// roles as break-glass for humans.
	PlatformRoles []string

	// IsAgent reports that this caller is an enrolled agent identity acting
	// for a human, rather than the human themselves.
	IsAgent bool
	// OwnerPersonID is the human at the root of this caller's ownership
	// family — the caller themselves when IsAgent is false.
	OwnerPersonID string
	// PrincipalIDs is that family: the owner plus every live agent they run,
	// the caller included. DexID derives it (agent_credential lives there and
	// nowhere else); a consuming service only compares against it.
	PrincipalIDs []string

	// focusTenantID is this REQUEST's tenant focus, from the X-Tenant-Focus
	// header (story ebad1958; the shell's tenant-focus contract). Empty means
	// all-tenants, which is the header being absent.
	//
	// Unexported, and set only by WithTenantFocus, because focus must arrive
	// from the transport and from nowhere else — the same derivation law
	// ADR-0001 §13 applies to actor identity. A field a handler could assign
	// is a field a handler can widen, and the entire point of this control is
	// that widening takes an explicit act at the boundary rather than being
	// available anywhere a struct is in scope.
	focusTenantID string

	// BearerToken is the caller's own already-validated Supabase token,
	// stashed here (by the Gate, after ValidateJWT and FetchContext both
	// succeed) so a handler can make a SECOND identity-plane call on the
	// caller's behalf without asking them to send credentials twice — for
	// example resolving a person id to a display name through DexID's
	// self-service tenant roster, which is a per-caller-visibility endpoint
	// rather than a service-to-service one.
	BearerToken string
}

// IsOwnWork reports whether authorID belongs to this caller's ownership
// family — them, the human who runs them, or that human's other agents.
//
// Agents are deliberately separate persons, which is what makes attribution
// honest. The cost is that "did you create this?" answers no for work the
// person did by hand a minute earlier, and for work their other assistant
// filed. The family is what makes that question mean what people expect it
// to mean, without letting an agent reach anyone else's work.
//
// An empty authorID is never own work. That covers every record imported from
// an old tracker, where the author survived only as a display name: those
// cannot be proven to belong to anyone, and guessing from a name is exactly
// the wrong instinct ("Andrew Damico" and "Andrew D'Amico" are the same
// person and different strings).
func (a Access) IsOwnWork(authorID string) bool {
	if authorID == "" {
		return false
	}
	for _, id := range a.PrincipalIDs {
		if id == authorID {
			return true
		}
	}
	// Falls back to identity when DexID told us nothing about a family, so a
	// caller can always act on what they themselves created.
	return len(a.PrincipalIDs) == 0 && authorID == a.PersonID
}

// ─── tenant focus ────────────────────────────────────────────────────────
//
// FOCUS IS NOT AUTHORIZATION, and this file is where that sentence has to be
// true rather than merely written down. The shell's contract (rule 4): the
// header says what the person chose to LOOK AT, and must never influence what
// they are ALLOWED to see.
//
// So the two questions are answered by two different methods, and they read
// different sets:
//
//   - TenantIDs() — "what may this REQUEST return" — is the focused set, the
//     intersection of membership with the header. Query call sites scope with
//     it, and every one of them narrows automatically. That is the whole
//     story: a screen cannot fetch outside the focus by omission, because
//     there is no longer anything to omit.
//   - HasTenant() and AuthorizedTenantIDs() — "what is this CALLER entitled
//     to" — read membership, unfocused. Their call sites ask "may I create
//     this thing in the tenant the body names", which is an authorization
//     question about an explicit act. Narrowing it would make focus decide
//     authorization, which rule 4 forbids, and would break legitimate
//     cross-tenant acts (moving a package to another tenant is the clearest
//     one) for no gain in what any screen displays.
//
// The split is the reason focus can be applied at one seam without auditing
// every call site: reads narrow because they all go through one method,
// writes keep asking the question they were already asking.
//
// Role and entitlement decisions belong to the SECOND family. See scope.go.

// WithTenantFocus returns a copy of the context narrowed to tenantID.
//
// The intersection is the ONLY operation: a focus naming a tenant the caller
// is not a member of yields an EMPTY focused set — empty results, never a
// refusal, because a distinct "forbidden" would confirm that tenant exists to
// somebody with no access to it.
//
// An empty tenantID means all-tenants and is what an ABSENT header produces.
// A header that is PRESENT but blank does not reach here as empty — see
// ReadTenantFocus, which fails that case closed rather than treating it as
// absence.
func (a Access) WithTenantFocus(tenantID string) *Access {
	a.focusTenantID = tenantID
	return &a
}

// TenantFocus reports this request's focus, empty for all-tenants. Exposed so
// a handler can ECHO what was applied — a response that cannot say which
// scope produced it is one nobody can debug — never so it can be re-derived.
func (a Access) TenantFocus() string { return a.focusTenantID }

// HasTenant reports whether the caller is licensed+member for tenantID.
//
// DELIBERATELY UNFOCUSED. This is the authorization question; see the block
// comment above.
func (a Access) HasTenant(tenantID string) bool {
	for _, t := range a.Tenants {
		if t.TenantID == tenantID {
			return true
		}
	}
	return false
}

// AuthorizedTenantIDs is every tenant the caller is a member of, IGNORING
// focus. Use it only where the question is about entitlement rather than about
// what this request should return; TenantIDs is what a query scopes by.
func (a Access) AuthorizedTenantIDs() []string {
	ids := make([]string, len(a.Tenants))
	for i, t := range a.Tenants {
		ids[i] = t.TenantID
	}
	return ids
}

// TenantIDs returns the tenants THIS REQUEST may return data from: the
// caller's membership, intersected with the request's tenant focus.
//
// Unfocused, this is exactly the full membership, so a caller that never sets
// focus behaves as though focus did not exist. Focused, it is one element or
// none.
//
// NEVER NIL. An empty result is an explicit empty slice, because the predicate
// it feeds is `WHERE tenant_id IN $tenant_ids`, which matches nothing for an
// empty list — a fail-closed idiom by construction, rather than one that
// depends on how nil marshals.
func (a Access) TenantIDs() []string {
	authorized := a.AuthorizedTenantIDs()
	if a.focusTenantID == "" {
		return authorized
	}
	for _, id := range authorized {
		if id == a.focusTenantID {
			return []string{id}
		}
	}
	// Focused on a tenant this caller is not a member of. Empty, not
	// forbidden: the request returns nothing and confirms nothing.
	return []string{}
}

// ─── the new facts: entitlements and roles ───────────────────────────────

// Membership returns the caller's membership record for tenantID.
func (a Access) Membership(tenantID string) (TenantMembership, bool) {
	for _, t := range a.Tenants {
		if t.TenantID == tenantID {
			return t, true
		}
	}
	return TenantMembership{}, false
}

// EntitlementsFor returns the feature keys tenantID holds, as DexID reported
// them. Nil for a tenant the caller is not a member of — which is not the same
// as an empty slice for a tenant that simply has none provisioned, and the
// difference is what EntitlementsProvisioned exists to state.
func (a Access) EntitlementsFor(tenantID string) []string {
	if m, ok := a.Membership(tenantID); ok {
		return m.Entitlements
	}
	return nil
}

// HasEntitlement reports whether tenantID holds featureKey.
//
// Exact match only. Feature keys are opaque identifiers in a namespaced
// vocabulary, and a prefix or wildcard match here would quietly turn
// "ai.execution_cycles.create" into a grant of everything under ai.
func (a Access) HasEntitlement(tenantID, featureKey string) bool {
	for _, key := range a.EntitlementsFor(tenantID) {
		if key == featureKey {
			return true
		}
	}
	return false
}

// EntitlementsProvisioned reports whether tenantID has ANY entitlement data at
// all.
//
// This distinguishes "this tenant is not entitled to that feature" from "no
// plan has been assigned to this tenant yet, so the entitlement table has
// nothing to say about it". The two look identical to HasEntitlement and must
// not be treated identically while entitlement data is still being seeded:
// enforcing against an empty table denies everything to everyone.
func (a Access) EntitlementsProvisioned(tenantID string) bool {
	return len(a.EntitlementsFor(tenantID)) > 0
}

// RolesFor returns every role the caller holds that is meaningful in
// tenantID: their platform roles, plus their membership role in that tenant.
//
// The two axes are deliberately unioned rather than kept separate, because a
// route wants to ask one question ("is this caller admin-ish here?"), and
// because the two axes have different reach — see Access.PlatformRoles on why
// the tenant axis is the one that survives agent delegation.
func (a Access) RolesFor(tenantID string) []string {
	roles := make([]string, 0, len(a.PlatformRoles)+1)
	roles = append(roles, a.PlatformRoles...)
	if m, ok := a.Membership(tenantID); ok && m.Role != "" {
		roles = append(roles, m.Role)
	}
	return roles
}

// HasAnyRole reports whether the caller holds at least one of want within
// tenantID.
func (a Access) HasAnyRole(tenantID string, want ...string) bool {
	held := a.RolesFor(tenantID)
	for _, w := range want {
		for _, h := range held {
			if h == w {
				return true
			}
		}
	}
	return false
}
