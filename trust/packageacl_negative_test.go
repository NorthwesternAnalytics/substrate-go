package trust

import (
	"context"
	"testing"
)

// THE NEGATIVE SUITE — INC-2 (nw#3059), the acceptance list of nw#3050
// generalized to all principals, and the part of this feature that is worth
// more than the rest of it put together.
//
// # Why a negative suite is the load-bearing test and a positive one is not
//
// Every positive test here has a cheap way to pass: return admin for
// everybody. An evaluator that has quietly widened passes ALL of them and
// looks healthy. Only the denials distinguish an authorization system from a
// function that returns yes — and a denial that stops being a denial is
// exactly the failure that surfaces years later as a disclosure bug, when the
// semantics can no longer be changed. Decision d276afe2 says a published
// algebra is what makes the negative-test list PROVABLE; this file is that
// list, and every case cites the ruling it enforces so the argument can be
// checked line by line rather than taken on trust.
//
// # The shape: role × verb class, and the deny is the assertion
//
// The role×verb table (ccf3266a [2/12]) defines four verb classes over an
// ordered role chain. So the negative suite is that cross product: for each
// principal shape, the level it resolves to, and then the verb classes it must
// be REFUSED. Written table-driven so adding a role or a class forces every
// combination to be answered rather than the interesting ones being picked.
//
// # One trap, stated once, because INC-1 lost twenty minutes to it
//
// On an UNBROKEN tree every tenant member already resolves to the implicit
// tenant-root admin default, which masks whatever the entries say; and every
// outsider hits the cross-tenant comment cap, which masks it differently. A
// test about denial therefore measures the wrong conjunct unless the fixture
// first gets the default out of the way. aclSealedTree() is how — the root's
// inheritance broken, which is exactly what an owner does in real life to make
// a branch's entries the whole story.

// verbClass is one row of ccf3266a's table: a family of verbs and the minimum
// level that may call them.
type verbClass struct {
	name string
	min  Level
}

// theFourVerbClasses is the contract's table, as data.
var theFourVerbClasses = []verbClass{
	{"read (list/get/journals/export/gates/ancestry/resolve)", LevelRead},
	{"comment (discussion create, edit-own)", LevelComment},
	{"read_write (create/update/transition/append/rank/assign)", LevelReadWrite},
	{"admin (ACL entries, inherit, groups, lifecycle, delete, re-home)", LevelAdmin},
}

// assertDenied is the single assertion this whole file makes.
//
// It goes through RequirePackageAccess and DecideFor — the SAME seam a handler
// uses — rather than comparing levels directly. Comparing levels would test
// the ordering, which is already tested; going through the Requirement tests
// the thing that actually refuses a request, which is what a disclosure bug
// would have to get past.
func assertDenied(t *testing.T, what string, have Level, class verbClass, access *Access, ruling string) {
	t.Helper()
	req := RequirePackageAccess(class.min, have)
	d := DecidePackageAccess(access, testTenant, req)
	if d.Allowed() {
		t.Errorf("DENIAL MISSING — %s holds %q and was ALLOWED %s (needs %q).\n"+
			"    Ruling: %s\n"+
			"    A negative case that stops failing is the shape a disclosure bug arrives in: "+
			"nothing looks broken, and somebody sees something they should not.",
			what, have, class.name, class.min, ruling)
	}
}

// assertAllowed is its counterpart, and it exists so a denial cannot be
// achieved by refusing everybody — which would pass every test above.
func assertAllowed(t *testing.T, what string, have Level, class verbClass, access *Access, ruling string) {
	t.Helper()
	req := RequirePackageAccess(class.min, have)
	if d := DecidePackageAccess(access, testTenant, req); !d.Allowed() {
		t.Errorf("%s holds %q and was REFUSED %s (needs %q) — ruling: %s.\n"+
			"    Refusing everybody passes every negative case; this is the guard against that.",
			what, have, class.name, class.min, ruling)
	}
}

// ─── 1. the role ladder: every role is denied every class above it ───────

func TestEachRoleIsDeniedEveryVerbClassAboveIt(t *testing.T) {
	// The whole cross product, none skipped. ccf3266a [2/12]: the chain is
	// read ⊂ comment ⊂ read_write ⊂ admin, so a role's denials are exactly
	// the classes ranked above it — and its allowances exactly those at or
	// below. Asserting BOTH directions is what stops "deny everything" from
	// being a passing implementation.
	roles := []Level{LevelNone, LevelRead, LevelComment, LevelReadWrite, LevelAdmin}
	access := aclMember("p1")

	for _, have := range roles {
		for _, class := range theFourVerbClasses {
			if have.AtLeast(class.min) {
				assertAllowed(t, "a principal at "+string(have), have, class, access,
					"ccf3266a [2/12] — the chain is a superset chain")
				continue
			}
			assertDenied(t, "a principal at "+string(have), have, class, access,
				"ccf3266a [2/12] — read ⊂ comment ⊂ read_write ⊂ admin")
		}
	}
}

func TestLevelNoneIsDeniedEVERYVerbClass(t *testing.T) {
	// Called out separately from the ladder above because LevelNone is not a
	// grantable role — it is the ABSENCE of access (packageacl.go), the value
	// effective() returns when nothing reaches. If any verb class were
	// callable at none, the entire model would be open by default and every
	// other test in this package would be measuring decoration.
	for _, class := range theFourVerbClasses {
		assertDenied(t, "a principal with NO access", LevelNone, class, aclMember("p1"),
			"packageacl.go — LevelNone is the absence of access and is not grantable")
	}
}

// ─── 2. break inheritance: the branch is cut for everyone not named ──────

func TestBreakInheritanceDeniesAPrincipalGrantedOnlyAbove(t *testing.T) {
	// 3d9b9b88 [4/12]: inherit=false ⇒ the node's effective set is its
	// explicit entries ONLY. Andrew's words — "revoke inheritance on that
	// specific branch only" — and the acceptance scenario's whole mechanism.
	nodes := aclSealedTree()
	nodes["project"] = NodeACL{NodeID: "project", ParentIDs: []string{"program", "program2"}, Inherit: false}

	f := &fakeACLStore{
		nodes:    nodes,
		presence: true,
		entries: map[string][]ACLEntry{
			// Granted on the PROGRAM, which the project no longer inherits.
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "outsider-to-branch", LevelAdmin)},
			// And somebody named ON the project, so the break is not simply
			// "nothing resolves here" — the branch is alive, just narrower.
			"project": {aclEntryOf("e2", "project", PrincipalPerson, "in-branch", LevelReadWrite)},
		},
	}

	denied := aclMember("outsider-to-branch")
	have := aclResolve(t, f, denied, "project")
	for _, class := range theFourVerbClasses {
		assertDenied(t, "a principal granted admin ONLY on the parent program", have, class, denied,
			"3d9b9b88 [4/12] — inherit=false means explicit entries only")
	}

	// And the counterpart, so the break is not passing by refusing everyone.
	allowed := aclMember("in-branch")
	haveIn := aclResolve(t, f, allowed, "project")
	assertAllowed(t, "the principal named ON the broken branch", haveIn, theFourVerbClasses[2], allowed,
		"3d9b9b88 [4/12] — the node's own entries still apply")
	assertDenied(t, "the principal named ON the broken branch at read_write", haveIn, theFourVerbClasses[3], allowed,
		"ccf3266a [2/12] — read_write is not admin")
}

// ─── 3. the diamond: a union, never an intersection ──────────────────────

func TestTheDiamondDeniesWhenNEITHERParentGrants(t *testing.T) {
	// 3d9b9b88 [4/12]: diamonds UNION over all parents. The negative case is
	// the one that matters: union means a principal granted on neither parent
	// is still denied, and a bug that turned the union into "reachable via any
	// path" would show up here and nowhere else.
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "via-one", LevelReadWrite)},
		},
	}

	nobody := aclMember("via-neither")
	have := aclResolve(t, f, nobody, "project")
	for _, class := range theFourVerbClasses {
		assertDenied(t, "a principal granted on NEITHER parent of the diamond", have, class, nobody,
			"3d9b9b88 [4/12] — a diamond unions the parents' grants, it does not confer any")
	}

	// The union direction, as the guard against deny-everything.
	someone := aclMember("via-one")
	assertAllowed(t, "a principal granted on ONE parent of the diamond",
		aclResolve(t, f, someone, "project"), theFourVerbClasses[2], someone,
		"3d9b9b88 [4/12] — union over all parents")
}

// ─── 4. group-granted vs direct ──────────────────────────────────────────

func TestAGroupGrantDeniesANonMemberOfThatGroup(t *testing.T) {
	// 0bfcd559 [1/12]: a security group is a principal kind. The negative
	// case: the group's grant must reach its MEMBERS and nobody else. This is
	// Andrew's acceptance scenario exactly — agent A in group G works, agent B
	// with the same owner does not.
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		entries: map[string][]ACLEntry{
			"project": {aclEntryOf("e1", "project", PrincipalGroup, "group-G", LevelReadWrite)},
		},
		groups: map[string][]string{"agent-A": {"group-G"}},
	}

	agentB := aclMember("agent-B")
	have := aclResolve(t, f, agentB, "project")
	for _, class := range theFourVerbClasses {
		assertDenied(t, "agent B, same owner, NOT in group G", have, class, agentB,
			"0bfcd559 [1/12] + nw#3054 acceptance — a group grant reaches its members only")
	}

	agentA := aclMember("agent-A")
	assertAllowed(t, "agent A, a member of group G",
		aclResolve(t, f, agentA, "project"), theFourVerbClasses[2], agentA,
		"0bfcd559 [1/12] — the group's grant reaches its members")
}

// ─── 5. revoked / tombstoned entries confer nothing ──────────────────────

func TestATombstonedEntryConfersNOTHING(t *testing.T) {
	// The revocation path, tested for what is ACTUALLY true here rather than
	// for what I first assumed.
	//
	// I wrote this test expecting to hand the evaluator a revoked entry and
	// watch it ignore one. It cannot: ACLEntry HAS NO RevokedAt FIELD.
	// Tombstone filtering is the STORE's contract — PackageACLStore.EntriesFor
	// is specified to return LIVE entries — so by the time the evaluator sees
	// anything, a revoked entry is simply absent. Writing the test the way I
	// first imagined would have quietly asserted a filter that does not exist
	// at this layer, and passed.
	//
	// So this is the honest version: the fixture models the store AFTER a
	// tombstone, and the assertion is that revocation is TOTAL and IMMEDIATE —
	// an ex-member is denied every class, with no credential event anywhere
	// (50056838 [11/12] T2: removing a principal from an entry ends
	// authorization with the key untouched). The other half — that the store
	// really does filter tombstoned rows — is not provable without a database
	// and is proven by INC-1's live entry-revoke test against real tables.
	// Two layers, two proofs, neither pretending to be the other.
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		entries: map[string][]ACLEntry{
			// The ex-member's entry is GONE. Somebody else's remains, so the
			// node is still alive and this is not passing because the fixture
			// is empty.
			"project": {aclEntryOf("e2", "project", PrincipalPerson, "still-granted", LevelReadWrite)},
		},
	}

	ex := aclMember("ex-member")
	have := aclResolve(t, f, ex, "project")
	for _, class := range theFourVerbClasses {
		assertDenied(t, "a principal whose entry has been TOMBSTONED", have, class, ex,
			"50056838 [11/12] T2 — removing authorization is immediate, total, and needs no key event")
	}

	still := aclMember("still-granted")
	assertAllowed(t, "the principal whose entry was NOT revoked",
		aclResolve(t, f, still, "project"), theFourVerbClasses[2], still,
		"revoking one entry must not revoke the others")
}

// ─── 6. cross-tenant: capped at comment, so both write classes are denied ─

func TestACrossTenantPrincipalIsDeniedBothWriteClasses(t *testing.T) {
	// ccf3266a [2/12]: cross-tenant principals cap at comment in v1, matching
	// the guest epic's viewer|commenter promise. 67c69f0f [12/12] makes the
	// guest an ordinary entry rather than a second mechanism — so the cap is
	// the only thing standing between a guest and a write, and it is tested
	// as a DENIAL rather than as a level comparison.
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		entries: map[string][]ACLEntry{
			// Granted ADMIN deliberately. The cap must hold against an entry
			// that says otherwise, because that is the case a real mistake
			// produces.
			"project": {aclEntryOf("e1", "project", PrincipalPerson, "guest", LevelAdmin)},
		},
	}

	guest := aclOutsider("guest")
	have := aclResolve(t, f, guest, "project")

	assertAllowed(t, "a cross-tenant guest granted admin", have, theFourVerbClasses[0], guest,
		"67c69f0f [12/12] — the entry path extends to named outsiders")
	assertAllowed(t, "a cross-tenant guest granted admin", have, theFourVerbClasses[1], guest,
		"ccf3266a [2/12] — the cap is AT comment, not below it")
	assertDenied(t, "a cross-tenant guest granted admin", have, theFourVerbClasses[2], guest,
		"ccf3266a [2/12] — cross-tenant principals cap at comment in v1")
	assertDenied(t, "a cross-tenant guest granted admin", have, theFourVerbClasses[3], guest,
		"ccf3266a [2/12] — cross-tenant principals cap at comment in v1")
}

func TestAnUngrantedCrossTenantPrincipalIsDeniedEVERYTHING(t *testing.T) {
	// nw#1171 (Guest 2/5), absorbed here: the fail-closed read-path rail. A
	// cross-tenant principal with NO entry sees nothing at all — not a
	// narrower view, nothing.
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		entries: map[string][]ACLEntry{
			"project": {aclEntryOf("e1", "project", PrincipalPerson, "some-other-guest", LevelComment)},
		},
	}

	stranger := aclOutsider("stranger")
	have := aclResolve(t, f, stranger, "project")
	for _, class := range theFourVerbClasses {
		assertDenied(t, "an UNGRANTED cross-tenant principal", have, class, stranger,
			"nw#1171 absorbed by 67c69f0f [12/12] — no entry, no reach; fail closed")
	}
}

// ─── 7. the tenant-owner floor: the ONE principal never denied ───────────

func TestTheTenantOwnerFloorIsNeverDeniedAnyVerbClass(t *testing.T) {
	// ccf3266a [2/12]: the tenant owner/admin ALWAYS retains admin on every
	// node, break or no break. This is the inverse assertion of the whole
	// file, and it belongs here rather than with the positive tests because
	// of WHY the rule exists: Windows permits self-lockout and answers it
	// with "take ownership"; we never enter the state at all. An owner locked
	// out of their own record is an unrecoverable state, which is
	// Prime-Directive-adjacent — the accountable human must always be able to
	// see and repair the record.
	nodes := aclSealedTree()
	nodes["project"] = NodeACL{NodeID: "project", ParentIDs: []string{"program", "program2"}, Inherit: false}

	f := &fakeACLStore{nodes: nodes, presence: true, entries: map[string][]ACLEntry{
		"project": {aclEntryOf("e1", "project", PrincipalPerson, "somebody-else", LevelRead)},
	}}

	owner := aclTenantAdmin("the-owner")
	have := aclResolve(t, f, owner, "project")
	for _, class := range theFourVerbClasses {
		assertAllowed(t, "the TENANT OWNER on a branch that excludes them", have, class, owner,
			"ccf3266a [2/12] — the owner floor: unrecoverable-state prevention")
	}
}

func TestTheNegativeSuiteCoversEveryRoleAndEveryClass(t *testing.T) {
	// A guard on the suite itself. The failure this catches is a negative
	// suite that quietly stops covering a case — somebody deletes a test, the
	// package still passes, and nobody notices the hole. Counting is cheap and
	// "all four classes are exercised" is a fact rather than an impression.
	if len(theFourVerbClasses) != 4 {
		t.Fatalf("the verb-class table has %d rows, want the 4 of ccf3266a [2/12]",
			len(theFourVerbClasses))
	}
	seen := map[Level]bool{}
	for _, c := range theFourVerbClasses {
		seen[c.min] = true
	}
	for _, want := range []Level{LevelRead, LevelComment, LevelReadWrite, LevelAdmin} {
		if !seen[want] {
			t.Errorf("no verb class requires %q; the ladder tests cannot be exhaustive without it", want)
		}
	}
	_ = context.Background
}

// TestTheEntryPathIsNotVetoedByTenantMembership pins the defect the negative
// suite found, so that a later refactor cannot quietly reintroduce it.
//
// This is the test I would ask a reviewer to read second (after INC-1's
// TestShortCircuitAgreesWithTheFullPath). It asserts a DIFFERENCE between two
// functions, which is unusual, and the difference is the whole finding: the
// general decision path refuses a cross-tenant guest on tenant membership
// before the requirement is consulted, and the package-access path does not,
// because 67c69f0f [12/12] makes the formula an OR and the general path can
// only express the AND of its left disjunct.
//
// If someone "simplifies" DecidePackageAccess back into DecideFor, this test
// fails and says why. Without it, the only symptom would be that guests see
// nothing — which looks like the feature working correctly.
func TestTheEntryPathIsNotVetoedByTenantMembership(t *testing.T) {
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		entries: map[string][]ACLEntry{
			"project": {aclEntryOf("e1", "project", PrincipalPerson, "guest", LevelComment)},
		},
	}

	guest := aclOutsider("guest")
	have := aclResolve(t, f, guest, "project")
	if have != LevelComment {
		t.Fatalf("the guest resolves %q, want %q — the entry path is not admitting them at all, "+
			"which is a different (and worse) bug than the one this test is about", have, LevelComment)
	}

	req := RequirePackageAccess(LevelRead, have)

	// The general path refuses them. Asserted, not assumed: if this ever
	// starts allowing, the special path below is no longer needed and should
	// be deleted rather than left as folklore.
	if d := DecideFor(guest, testTenant, req); d.Allowed() {
		t.Errorf("DecideFor now ALLOWS a non-member; DecidePackageAccess exists only because it did not, " +
			"so either this is a widening of the general path or the special path is now dead code")
	} else if d.ReasonCode != ReasonTenantNotLicensed {
		t.Errorf("DecideFor refused with %q, want %q — the finding was specifically that a guest is "+
			"refused for a LICENSING reason that is not true of them", d.ReasonCode, ReasonTenantNotLicensed)
	}

	// The package path admits them, because the resolver already applied the
	// whole formula and returned a level that says so.
	if d := DecidePackageAccess(guest, testTenant, req); !d.Allowed() {
		t.Errorf("DecidePackageAccess REFUSED a guest holding %q on a read requirement (%s).\n"+
			"    67c69f0f [12/12]: readable = [member path] OR [entry path]. Refusing here collapses "+
			"the OR back to its left disjunct and un-absorbs epic nw#1169.", have, d.ReasonCode)
	}

	// And the relaxation must not leak to other requirement kinds: a role
	// question from a non-member is still refused on membership, because
	// there the precondition is load-bearing and correct.
	roleReq := RequireRole("member", RoleSet{Tenant: []string{"member"}})
	if d := DecidePackageAccess(guest, testTenant, roleReq); d.Allowed() {
		t.Error("DecidePackageAccess allowed a non-package requirement from a non-member; " +
			"the relaxation is for package access alone and must never become a way around " +
			"the membership gate for role and entitlement questions")
	}
}

// THE NEGATIVE HALF THE DIRECTOR ASKED FOR (review e15d09b2, ruling (a)).
//
// TestTheEntryPathIsNotVetoedByTenantMembership above proves that a
// cross-tenant guest WITH an entry is admitted. On its own that test is
// readable — wrongly — as "DecidePackageAccess lets guests bypass tenancy".
// It does not, and the difference is the entire safety of the fix: what was
// removed is a membership veto applied BEFORE the requirement was consulted,
// not the requirement itself. Reaching any level above none still requires
// the RESOLVER to have granted it, through the member path or the entry path.
//
// So this asserts the other side. A non-member with NO entry resolves to
// LevelNone and is refused by BOTH functions. If somebody ever widens
// DecidePackageAccess into an actual bypass, this is the test that fails —
// and without it, the only symptom would be an outsider quietly seeing
// everything, which is the failure mode that surfaces years later.
func TestANonMemberWithNoEntryIsStillRefusedByBothPaths(t *testing.T) {
	f := &fakeACLStore{
		nodes:    aclSealedTree(),
		presence: true,
		// Deliberately NOT empty: there IS a live entry on the node, it just
		// names somebody else. An empty entry map would also pass this test
		// while proving less — it would leave open whether the refusal came
		// from "no entry for you" or from "no entries at all", and only the
		// first is the property being claimed.
		entries: map[string][]ACLEntry{
			"project": {aclEntryOf("e1", "project", PrincipalPerson, "someone-else", LevelAdmin)},
		},
	}

	outsider := aclOutsider("nobody")

	// The resolver is where the OR actually lives, so it is where the
	// refusal has to originate. Assert that first: if this ever returns
	// anything above none, the two Decide assertions below would be testing
	// a threshold rather than the formula.
	have := aclResolve(t, f, outsider, "project")
	if have != LevelNone {
		t.Fatalf("a non-member with no entry resolved %q, want %q — the resolver is admitting "+
			"somebody through neither the member path nor the entry path, which is a widening "+
			"of 67c69f0f's formula itself and not merely of the decision seam", have, LevelNone)
	}

	req := RequirePackageAccess(LevelRead, have)

	if d := DecideFor(outsider, testTenant, req); d.Allowed() {
		t.Error("DecideFor ALLOWED a non-member with no entry")
	}

	// The one that matters. DecidePackageAccess drops the membership
	// precondition, so if the threshold check were also wrong this is where
	// an outsider would walk in.
	if d := DecidePackageAccess(outsider, testTenant, req); d.Allowed() {
		t.Errorf("DecidePackageAccess ALLOWED a non-member holding %q on a READ requirement.\n"+
			"    The fix removed a membership VETO that ran before the requirement was consulted; "+
			"it did not remove the requirement. A principal the resolver grants nothing to must be "+
			"refused by the threshold, exactly as before — otherwise this is a bypass and not an OR.", have)
	}

	// And at every other class too, so the test cannot pass because read
	// happens to be special-cased somewhere.
	for _, min := range []Level{LevelComment, LevelReadWrite, LevelAdmin} {
		r := RequirePackageAccess(min, have)
		if d := DecidePackageAccess(outsider, testTenant, r); d.Allowed() {
			t.Errorf("DecidePackageAccess ALLOWED a non-member with no entry at %q", min)
		}
	}
}
