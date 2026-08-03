package trust

import "testing"

// The decision engine, at the seam that decides. Every test here is a rule the
// module promises to every backend that imports it, so they are written as
// properties of Decide rather than of any one route.

func member(tenantID, role string, entitlements ...string) TenantMembership {
	return TenantMembership{TenantID: tenantID, Role: role, Entitlements: entitlements}
}

func caller(tenants ...TenantMembership) *Access {
	return &Access{PersonID: "p1", Tenants: tenants}
}

var reports = RequireFeature("demo.reports.export")

// ─── entitlements ────────────────────────────────────────────────────────

func TestAnEntitledTenantIsAllowed(t *testing.T) {
	access := caller(member("alpha", "member", "demo.reports.export"))

	d := Decide(access, reports)
	if !d.Allowed() {
		t.Fatalf("entitled tenant refused: %+v", d)
	}
	if d.ReasonCode != ReasonAllowed || d.TenantID != "alpha" {
		t.Errorf("decision = %+v, want allowed for alpha", d)
	}
	if d.Source != DecisionSource {
		t.Errorf("Source = %q, want %q so a client can tell a backend decision from its own",
			d.Source, DecisionSource)
	}
}

// FAIL CLOSED. A tenant holding other entitlements but not this one is
// refused, and the refusal names the cause the client engine would have named.
func TestAnUnentitledTenantIsRefusedAsNotEntitled(t *testing.T) {
	access := caller(member("alpha", "member", "demo.reports.view"))

	d := Decide(access, reports)
	if d.Allowed() {
		t.Fatal("a tenant without the key was allowed — the gate does not fail closed")
	}
	if d.ReasonCode != ReasonTenantNotEntitled {
		t.Errorf("ReasonCode = %q, want %q", d.ReasonCode, ReasonTenantNotEntitled)
	}
	if d.HTTPStatus() != 403 {
		t.Errorf("HTTPStatus = %d, want 403", d.HTTPStatus())
	}
}

// Matching is EXACT. A key is an opaque identifier in a namespaced
// vocabulary; a prefix match would turn one grant into a grant of everything
// beneath it.
func TestEntitlementMatchingIsExact(t *testing.T) {
	for _, held := range []string{"demo.reports", "demo.reports.export.all", "DEMO.REPORTS.EXPORT"} {
		access := caller(member("alpha", "member", held))
		if Decide(access, reports).Allowed() {
			t.Errorf("holding %q satisfied %q; matching must be exact", held, "demo.reports.export")
		}
	}
}

// A caller with no memberships is refused before any feature is considered:
// there is nothing to judge a tenant-scoped requirement against.
func TestACallerWithNoTenantsIsNotLicensed(t *testing.T) {
	d := Decide(caller(), reports)
	if d.ReasonCode != ReasonTenantNotLicensed {
		t.Errorf("ReasonCode = %q, want %q", d.ReasonCode, ReasonTenantNotLicensed)
	}
}

// ─── the provisioned variant ─────────────────────────────────────────────

// The whole point: enforcement can land before the data it enforces against,
// without denying everything to everyone on the day it ships.
func TestWhenProvisionedAllowsATenantWithNoEntitlementDataAtAll(t *testing.T) {
	access := caller(member("alpha", "member")) // no entitlements provisioned
	req := RequireFeatureWhenProvisioned("ai.execution_cycles.create")

	if d := Decide(access, req); !d.Allowed() {
		t.Fatalf("an unprovisioned tenant was refused: %+v — this brings the product down "+
			"for its own authors on the day entitlements ship", d)
	}
	// And the strict form refuses the same caller, which is the difference
	// between the two constructors stated as a test.
	if Decide(access, RequireFeature("ai.execution_cycles.create")).Allowed() {
		t.Error("RequireFeature allowed an unprovisioned tenant; only the WhenProvisioned form may")
	}
}

// The moment a tenant has ANY entitlement, the provisional form becomes the
// strict one FOR THAT TENANT — with no code change. That automatic switch-on
// is what makes the escape hatch honest rather than permanent.
func TestWhenProvisionedEnforcesAsSoonAsTheTenantHasAnyEntitlement(t *testing.T) {
	req := RequireFeatureWhenProvisioned("ai.execution_cycles.create")

	entitledToSomethingElse := caller(member("alpha", "member", "portfolidex.programs.view"))
	d := Decide(entitledToSomethingElse, req)
	if d.Allowed() {
		t.Fatal("a provisioned tenant lacking the key was allowed; enforcement must switch " +
			"on with the data")
	}
	if d.ReasonCode != ReasonTenantNotEntitled {
		t.Errorf("ReasonCode = %q, want %q", d.ReasonCode, ReasonTenantNotEntitled)
	}

	entitled := caller(member("alpha", "member", "ai.execution_cycles.create"))
	if !Decide(entitled, req).Allowed() {
		t.Error("a tenant holding the key was refused")
	}
}

// ─── roles ───────────────────────────────────────────────────────────────

var adminOnly = RequireRole("administrator", RoleSet{
	Tenant:   []string{"owner", "admin"},
	Platform: []string{"platform.admin"},
})

func TestTheTenantRoleAxisSatisfiesARoleRequirement(t *testing.T) {
	if !Decide(caller(member("alpha", "admin")), adminOnly).Allowed() {
		t.Error("a tenant admin was refused")
	}
	if !Decide(caller(member("alpha", "owner")), adminOnly).Allowed() {
		t.Error("a tenant owner was refused")
	}
}

// THE GAP THIS CLOSES: a plain member could delete anything in their tenant.
func TestAPlainMemberIsRefusedAnAdminRequirement(t *testing.T) {
	d := Decide(caller(member("alpha", "member")), adminOnly)
	if d.Allowed() {
		t.Fatal("a plain member satisfied an admin requirement — the any-member-can-delete " +
			"gap is still open")
	}
	if d.ReasonCode != ReasonRoleDenied {
		t.Errorf("ReasonCode = %q, want %q", d.ReasonCode, ReasonRoleDenied)
	}
}

func TestThePlatformRoleAxisSatisfiesARoleRequirement(t *testing.T) {
	access := caller(member("alpha", "member"))
	access.PlatformRoles = []string{"platform.member", "platform.admin"}

	if !Decide(access, adminOnly).Allowed() {
		t.Error("a platform admin was refused; the platform axis is break-glass and must work")
	}
}

// The implied role every person holds must not satisfy anything.
func TestPlatformMemberAloneSatisfiesNothing(t *testing.T) {
	access := caller(member("alpha", "member"))
	access.PlatformRoles = []string{"platform.member"}

	if Decide(access, adminOnly).Allowed() {
		t.Error("platform.member — which every active person holds — satisfied an admin gate")
	}
}

// A role gate naming no roles refuses everyone. A misconfiguration must fail
// loudly rather than admit everyone silently.
func TestAnEmptyRoleSetSatisfiesNobody(t *testing.T) {
	access := caller(member("alpha", "owner"))
	access.PlatformRoles = []string{"platform.admin"}

	if Decide(access, RequireRole("misconfigured", RoleSet{})).Allowed() {
		t.Error("an empty RoleSet admitted a caller; it must refuse everyone")
	}
}

// ─── tenant-scope resolution ─────────────────────────────────────────────

// The ordinary case: the shell sets X-Tenant-Focus, so the decision is judged
// against exactly the organisation the person is looking at.
func TestFocusSelectsTheTenantTheDecisionIsJudgedAgainst(t *testing.T) {
	access := caller(member("alpha", "admin"), member("beta", "member")).
		WithTenantFocus("beta")

	d := Decide(access, adminOnly)
	if d.Allowed() {
		t.Fatal("focused on beta, where the caller is a plain member, and yet allowed — " +
			"alpha's admin role leaked across the focus")
	}
	if d.TenantID != "beta" {
		t.Errorf("TenantID = %q, want beta", d.TenantID)
	}
}

// Focus on a tenant the caller does not belong to. Note the asymmetry with
// TenantIDs(), which answers the same situation with an empty READ scope: a
// read that returns nothing confirms nothing, but an ACT must be answered.
func TestFocusOnANonMemberTenantIsNotLicensed(t *testing.T) {
	access := caller(member("alpha", "admin")).WithTenantFocus("someone-elses-tenant")

	d := Decide(access, adminOnly)
	if d.Allowed() {
		t.Fatal("a focus on a non-member tenant was allowed using another tenant's role")
	}
	if d.ReasonCode != ReasonTenantNotLicensed {
		t.Errorf("ReasonCode = %q, want %q", d.ReasonCode, ReasonTenantNotLicensed)
	}
	if d.TenantID != "" {
		t.Errorf("TenantID = %q; a refusal must not echo a tenant the caller has no access to",
			d.TenantID)
	}
}

// Unfocused and single-tenant — the overwhelmingly common case for an agent
// or an MCP client, neither of which sends the header. It must behave exactly
// as though the header had named that tenant.
func TestAnUnfocusedSingleTenantCallerIsJudgedAgainstThatTenant(t *testing.T) {
	if !Decide(caller(member("alpha", "admin")), adminOnly).Allowed() {
		t.Error("an unfocused single-tenant admin was refused; a client that never sends " +
			"the focus header must still be able to act")
	}
	if Decide(caller(member("alpha", "member")), adminOnly).Allowed() {
		t.Error("an unfocused single-tenant member was allowed")
	}
}

// Unfocused across several tenants, satisfied in ALL of them: allowed. The
// answer is the same whichever one the request meant, so there is nothing to
// disambiguate.
func TestUnfocusedAndSatisfiedEverywhereIsAllowed(t *testing.T) {
	access := caller(member("alpha", "admin"), member("beta", "owner"))
	if !Decide(access, adminOnly).Allowed() {
		t.Error("a caller who is admin of every organisation they belong to was refused")
	}
}

// Unfocused across several tenants, satisfied in NONE: the requirement's own
// refusal, not focus_required. There is nothing focusing would fix.
func TestUnfocusedAndSatisfiedNowhereGivesTheRequirementsOwnReason(t *testing.T) {
	access := caller(member("alpha", "member"), member("beta", "member"))
	if d := Decide(access, adminOnly); d.ReasonCode != ReasonRoleDenied {
		t.Errorf("ReasonCode = %q, want %q — focusing would not help this caller",
			d.ReasonCode, ReasonRoleDenied)
	}
}

// THE MIXED CASE, and the reason resolveScope quantifies universally.
//
// Allowing here would hand the permissive organisation's answer to the
// restrictive one — an admin of their own sandbox deleting records in an
// organisation where they are a plain member, which is precisely the gap this
// module was extracted to close.
func TestUnfocusedAndMixedAsksTheCallerToNarrow(t *testing.T) {
	access := caller(member("alpha", "admin"), member("beta", "member"))

	d := Decide(access, adminOnly)
	if d.Allowed() {
		t.Fatal("mixed authority across organisations was resolved as allowed; admin of one " +
			"organisation must not act in another")
	}
	if d.ReasonCode != ReasonFocusRequired {
		t.Errorf("ReasonCode = %q, want %q — the caller can fix this by choosing an organisation",
			d.ReasonCode, ReasonFocusRequired)
	}
	if d.Remediation == "" {
		t.Error("focus_required carried no remediation; it is the one refusal the caller can act on")
	}
}

// ─── DecideFor: the tenant the body named ────────────────────────────────

// A handler that already knows which tenant the act targets must not have it
// re-derived from header scope — the body is more specific than the header.
func TestDecideForJudgesTheNamedTenantRegardlessOfFocus(t *testing.T) {
	access := caller(member("alpha", "admin"), member("beta", "member")).
		WithTenantFocus("alpha")

	if DecideFor(access, "beta", adminOnly).Allowed() {
		t.Error("DecideFor(beta) was answered using alpha's role because alpha was focused")
	}
	if !DecideFor(access, "alpha", adminOnly).Allowed() {
		t.Error("DecideFor(alpha) refused an admin of alpha")
	}
}

func TestDecideForRefusesATenantTheCallerDoesNotBelongTo(t *testing.T) {
	access := caller(member("alpha", "admin"))

	d := DecideFor(access, "gamma", adminOnly)
	if d.Allowed() {
		t.Fatal("DecideFor allowed an act in a tenant the caller is not a member of")
	}
	if d.ReasonCode != ReasonTenantNotLicensed {
		t.Errorf("ReasonCode = %q, want %q", d.ReasonCode, ReasonTenantNotLicensed)
	}
}

// A nil access — a handler reached outside the Gate, or a bug — must refuse,
// never panic and never allow.
func TestANilAccessIsRefused(t *testing.T) {
	if Decide(nil, adminOnly).Allowed() {
		t.Error("a nil access context was allowed")
	}
	if DecideFor(nil, "alpha", adminOnly).Allowed() {
		t.Error("a nil access context was allowed by DecideFor")
	}
}

// ─── the two sets stay two sets ──────────────────────────────────────────

// Rule 4 of the tenant-focus contract, restated for the new decision layer:
// focus says what the person chose to LOOK AT. It may select which tenant a
// decision is judged against — that is scope, and it is what the person asked
// for — but it must never change what they are ALLOWED to do elsewhere.
func TestDecidingUnderFocusDoesNotAlterAuthorization(t *testing.T) {
	access := caller(member("alpha", "admin"), member("beta", "member")).
		WithTenantFocus("beta")

	_ = Decide(access, adminOnly)

	if !access.HasTenant("alpha") || len(access.AuthorizedTenantIDs()) != 2 {
		t.Error("evaluating a decision under focus altered the caller's membership")
	}
	if !DecideFor(access, "alpha", adminOnly).Allowed() {
		t.Error("focus on beta revoked the caller's admin standing in alpha")
	}
}
