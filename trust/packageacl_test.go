package trust

import (
	"context"
	"testing"
)

// THE ALGEBRA SUITE. Every case here is derived from a ruling in the accepted
// INC-0 record on nw#3055, and each names the ruling it proves. That is not
// decoration: decision d276afe2 says an adopted published algebra is what
// makes the negative-test list PROVABLE, and a test that cannot cite the rule
// it enforces cannot be checked against the rule when the rule changes.
//
// No database. The evaluator is pure over four facts, so its whole semantics
// are testable against a fake store — which is also the strongest argument
// for the substrate/app split of decision f3774718: the mechanism can be
// proven once, here, for every consuming app.

// ─── the fake ────────────────────────────────────────────────────────────

type fakeACLStore struct {
	nodes    map[string]NodeACL
	entries  map[string][]ACLEntry
	groups   map[string][]string
	presence bool

	// call counters — proof P4 asserts the unrestricted path costs at most
	// ONE extra lookup, and "asserted by query-count test so 'unchanged'
	// covers latency class, not just bytes" (decision c8f0cd3d [8/12]).
	presenceCalls, chainCalls, entryCalls, groupCalls int
}

func (f *fakeACLStore) AncestorChains(_ context.Context, _ string, nodeIDs []string) (map[string]NodeACL, error) {
	f.chainCalls++
	out := map[string]NodeACL{}
	if len(nodeIDs) == 0 {
		for id, n := range f.nodes {
			out[id] = n
		}
		return out, nil
	}
	// The closure, exactly as the interface promises: requested nodes plus
	// every transitive CONTAINS-ancestor.
	var add func(id string)
	seen := map[string]bool{}
	add = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		n, ok := f.nodes[id]
		if !ok {
			return
		}
		out[id] = n
		for _, p := range n.ParentIDs {
			add(p)
		}
	}
	for _, id := range nodeIDs {
		add(id)
	}
	return out, nil
}

func (f *fakeACLStore) EntriesFor(_ context.Context, _ string, nodeIDs []string) (map[string][]ACLEntry, error) {
	f.entryCalls++
	out := map[string][]ACLEntry{}
	for _, id := range nodeIDs {
		out[id] = f.entries[id]
	}
	return out, nil
}

func (f *fakeACLStore) GroupMemberships(_ context.Context, _ string, personIDs []string) (map[string][]string, error) {
	f.groupCalls++
	out := map[string][]string{}
	for _, id := range personIDs {
		out[id] = f.groups[id]
	}
	return out, nil
}

func (f *fakeACLStore) TenantACLPresence(_ context.Context, _ string) (bool, error) {
	f.presenceCalls++
	return f.presence, nil
}

const testTenant = "acme"

// tree builds the shape most cases use:
//
//	portfolio ──> program ──> project
//	          └─> program2 ─┘        (project has TWO parents: a diamond)
func aclTree() map[string]NodeACL {
	return map[string]NodeACL{
		"portfolio": {NodeID: "portfolio", Inherit: true},
		"program":   {NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: true},
		"program2":  {NodeID: "program2", ParentIDs: []string{"portfolio"}, Inherit: true},
		"project":   {NodeID: "project", ParentIDs: []string{"program", "program2"}, Inherit: true},
	}
}

// aclSealedTree is aclTree with the ROOT's inheritance broken.
//
// Needed because of a fact that is easy to trip over and worth stating once:
// on an unbroken tree every tenant MEMBER already resolves to the implicit
// tenant-root default (admin), which masks whatever the entries say. So a
// test about how ENTRIES COMPOSE has to first get the default out of the way,
// and sealing the root is how an owner does exactly that in real life. The
// alternative — testing composition with an outsider — runs into the other
// conjunct, the cross-tenant comment cap, and measures that instead.
func aclSealedTree() map[string]NodeACL {
	nodes := aclTree()
	nodes["portfolio"] = NodeACL{NodeID: "portfolio", Inherit: false}
	return nodes
}

func aclMember(personID string) *Access {
	return &Access{
		PersonID:      personID,
		OwnerPersonID: personID,
		Tenants:       []TenantMembership{{TenantID: testTenant, Role: "member"}},
	}
}

func aclTenantAdmin(personID string) *Access {
	return &Access{
		PersonID:      personID,
		OwnerPersonID: personID,
		Tenants:       []TenantMembership{{TenantID: testTenant, Role: "admin"}},
	}
}

func aclAgentOf(agentID, ownerID string) *Access {
	return &Access{
		PersonID:      agentID,
		OwnerPersonID: ownerID,
		IsAgent:       true,
		// DexID copies the owner's memberships onto the agent, roles
		// included. Modelled faithfully here because a fake that got this
		// wrong would make the agent cap look like it worked for the wrong
		// reason.
		Tenants: []TenantMembership{{TenantID: testTenant, Role: "member"}},
	}
}

func aclOutsider(personID string) *Access {
	return &Access{PersonID: personID, OwnerPersonID: personID}
}

func aclEntryOf(id, node string, kind PrincipalKind, principal string, role Level) ACLEntry {
	return ACLEntry{ID: id, NodeID: node, PrincipalKind: kind, PrincipalID: principal, Role: role}
}

func aclResolve(t *testing.T, f *fakeACLStore, a *Access, node string) Level {
	t.Helper()
	lvl, err := NewACLResolver(f).Effective(context.Background(), a, testTenant, node)
	if err != nil {
		t.Fatalf("Effective(%s): %v", node, err)
	}
	return lvl
}

// ─── level ordering (decision ccf3266a [2/12]) ───────────────────────────

func TestTheRoleChainIsTotallyOrdered(t *testing.T) {
	// read ⊂ comment ⊂ read_write ⊂ admin. Asserted as the SUPERSET property
	// the decision states, not as four rank numbers, because the ranks are
	// the implementation and the chain is the contract.
	for i, lower := range GrantableLevels {
		for j, higher := range GrantableLevels {
			want := j >= i
			if got := higher.AtLeast(lower); got != want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", higher, lower, got, want)
			}
		}
	}
}

func TestNoneIsNotGrantableAndSatisfiesNothing(t *testing.T) {
	// The no-deny ruling as an executable fact (84a088d2, 3d9b9b88).
	if LevelNone.Grantable() {
		t.Fatal("LevelNone reported grantable: this model has no deny entries")
	}
	for _, l := range GrantableLevels {
		if LevelNone.AtLeast(l) {
			t.Errorf("LevelNone satisfied %s", l)
		}
	}
	if _, err := ParseGrantableLevel("none"); err == nil {
		t.Fatal("ParseGrantableLevel accepted \"none\"")
	}
	for _, l := range GrantableLevels {
		if got, err := ParseGrantableLevel(string(l)); err != nil || got != l {
			t.Errorf("ParseGrantableLevel(%q) = %q, %v", l, got, err)
		}
	}
}

func TestAnUnknownLevelFailsClosed(t *testing.T) {
	// A level from a future schema version, or a typo, must refuse rather
	// than admit.
	if Level("superuser").AtLeast(LevelRead) {
		t.Fatal("an unknown level satisfied read")
	}
}

// ─── inheritance (decision 3d9b9b88 [4/12]) ──────────────────────────────

func TestAGrantOnAnAncestorFlowsDown(t *testing.T) {
	f := &fakeACLStore{
		presence: true, nodes: aclTree(),
		entries: map[string][]ACLEntry{
			"portfolio": {aclEntryOf("e1", "portfolio", PrincipalPerson, "guest", LevelComment)},
		},
	}
	if got := aclResolve(t, f, aclOutsider("guest"), "project"); got != LevelComment {
		t.Fatalf("inherited grant = %q, want comment", got)
	}
}

func TestBreakingInheritanceIsTOTAL(t *testing.T) {
	// "a broken node takes nothing from above; there is no partial break."
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	nodes["project"] = NodeACL{NodeID: "project", ParentIDs: []string{"program"}, Inherit: true}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"portfolio": {aclEntryOf("e1", "portfolio", PrincipalPerson, "guest", LevelAdmin)},
		},
	}
	if got := aclResolve(t, f, aclOutsider("guest"), "program"); got != LevelNone {
		t.Fatalf("broken node = %q, want none: the break must be total", got)
	}
	if got := aclResolve(t, f, aclOutsider("guest"), "project"); got != LevelNone {
		t.Fatalf("below a broken node = %q, want none", got)
	}
}

func TestABreakCutsOffTheImplicitMemberDefaultToo(t *testing.T) {
	// This is nw#2291 — "private planning in one action: only me and the
	// people I name" — expressed in the algebra. Break, then grant one
	// person: every other member of the tenant loses the branch.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelAdmin)},
		},
	}
	if got := aclResolve(t, f, aclMember("alice"), "program"); got != LevelAdmin {
		t.Fatalf("named person on a broken branch = %q, want admin", got)
	}
	if got := aclResolve(t, f, aclMember("bob"), "program"); got != LevelNone {
		t.Fatalf("other member on a broken branch = %q, want none", got)
	}
	// ...and the rest of the tenant is untouched.
	if got := aclResolve(t, f, aclMember("bob"), "portfolio"); got != LevelAdmin {
		t.Fatalf("unbroken sibling branch = %q, want the member default", got)
	}
}

func TestBreakThenGrantWIDERIsLegal(t *testing.T) {
	// "may be narrower OR wider than the parent" — the Windows
	// disable-inheritance semantics, and the reason ancestor pages must list
	// broken descendants.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "guest", LevelComment)},
		},
	}
	if got := aclResolve(t, f, aclOutsider("guest"), "portfolio"); got != LevelNone {
		t.Fatalf("guest on the parent = %q, want none", got)
	}
	if got := aclResolve(t, f, aclOutsider("guest"), "program"); got != LevelComment {
		t.Fatalf("guest on the wider broken child = %q, want comment", got)
	}
}

func TestADiamondUNIONSRatherThanIntersects(t *testing.T) {
	// The ruling, and the two rejected alternatives, all in one case:
	// project has two parents; one grants admin and the other grants
	// nothing. Union answers admin. Intersection would answer none — which
	// would mean LINKING a node into a second parent silently revoked access,
	// a write to the graph revoking access as a side effect.
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelAdmin)},
		},
	}
	if got := aclResolve(t, f, aclMember("alice"), "project"); got != LevelAdmin {
		t.Fatalf("diamond = %q, want admin (union over all CONTAINS-parents)", got)
	}
	// program2, the other parent, grants nothing — so intersection would
	// have answered none here.
	if got := aclResolve(t, f, aclMember("alice"), "program2"); got != LevelNone {
		t.Fatalf("the ungranted parent = %q, want none", got)
	}
}

func TestLinkingIntoASecondParentNeverNarrows(t *testing.T) {
	// Monotonicity, stated as its own case because it is the PROPERTY the
	// union ruling was chosen for.
	oneParent := aclSealedTree()
	oneParent["project"] = NodeACL{NodeID: "project", ParentIDs: []string{"program"}, Inherit: true}
	entries := map[string][]ACLEntry{
		"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelReadWrite)},
	}
	before := aclResolve(t, &fakeACLStore{presence: true, nodes: oneParent, entries: entries}, aclMember("alice"), "project")
	after := aclResolve(t, &fakeACLStore{presence: true, nodes: aclSealedTree(), entries: entries}, aclMember("alice"), "project")
	if !after.AtLeast(before) {
		t.Fatalf("linking into a second parent narrowed %q to %q", before, after)
	}
}

func TestTheHIGHESTGrantOnAPathWinsNotTheNEAREST(t *testing.T) {
	// The sharpest divergence from the legacy per-package model (migration
	// 0051, superseded by Director ruling 278ead22), which resolved
	// NEAREST-grant-wins. On the same rows the two models disagree, and this
	// case is that disagreement: read near the node, admin higher up.
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"portfolio": {aclEntryOf("e1", "portfolio", PrincipalPerson, "alice", LevelAdmin)},
			"project":   {aclEntryOf("e2", "project", PrincipalPerson, "alice", LevelRead)},
		},
	}
	if got := aclResolve(t, f, aclMember("alice"), "project"); got != LevelAdmin {
		t.Fatalf("nearest-vs-highest = %q, want admin (union, not nearest-wins)", got)
	}
}

func TestACycleInContainmentTerminates(t *testing.T) {
	// A cycle is a data fault. Answering from the acyclic part is a better
	// response than hanging the request.
	f := &fakeACLStore{
		presence: true,
		nodes: map[string]NodeACL{
			"a": {NodeID: "a", ParentIDs: []string{"b"}, Inherit: true},
			"b": {NodeID: "b", ParentIDs: []string{"a"}, Inherit: true},
		},
		entries: map[string][]ACLEntry{
			"b": {aclEntryOf("e1", "b", PrincipalPerson, "guest", LevelRead)},
		},
	}
	if got := aclResolve(t, f, aclOutsider("guest"), "a"); got != LevelRead {
		t.Fatalf("cycle = %q, want read", got)
	}
}

// ─── principals (decision 0bfcd559 [1/12]) ───────────────────────────────

func TestAGroupGrantReachesItsMembers(t *testing.T) {
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		groups:  map[string][]string{"alice": {"engineering"}},
		entries: map[string][]ACLEntry{"program": {aclEntryOf("e1", "program", PrincipalGroup, "engineering", LevelReadWrite)}},
	}
	if got := aclResolve(t, f, aclMember("alice"), "project"); got != LevelReadWrite {
		t.Fatalf("group member = %q, want read_write", got)
	}
	if got := aclResolve(t, f, aclMember("carol"), "project"); got != LevelNone {
		t.Fatalf("non-member of the group = %q, want none", got)
	}
}

func TestAGroupIdNeverMatchesAPersonId(t *testing.T) {
	// principal_kind is part of the match key. Without it, a group named the
	// same as a person id would grant that person silently.
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{"program": {aclEntryOf("e1", "program", PrincipalGroup, "alice", LevelAdmin)}},
	}
	if got := aclResolve(t, f, aclMember("alice"), "program"); got != LevelNone {
		t.Fatalf("person matched a group entry with the same id: %q", got)
	}
}

func TestHumansAndAgentsArePersonEntriesAlike(t *testing.T) {
	// "no agent special-casing" — an entry naming an agent is an ordinary
	// person entry.
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"program": {
				aclEntryOf("e1", "program", PrincipalPerson, "agent-7", LevelReadWrite),
				aclEntryOf("e2", "program", PrincipalPerson, "alice", LevelReadWrite),
			},
		},
	}
	// The agent's row and the human's row have the SAME SHAPE and resolve the
	// same way. What differs is the cap, which is applied by the resolver and
	// is never a property of the row — proved separately below.
	if got := aclResolve(t, f, aclMember("alice"), "program"); got != LevelReadWrite {
		t.Fatalf("human person entry = %q, want read_write", got)
	}
	if got := aclResolve(t, f, aclAgentOf("agent-7", "alice"), "program"); got != LevelReadWrite {
		t.Fatalf("agent person entry = %q, want read_write", got)
	}
}

func TestTheAgentPostureOfNW3051IsPureData(t *testing.T) {
	// "allow no agents on a branch" = break + an entry for the member class
	// and none for the agent class. No second mechanism, no posture column.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalClass, ClassAllTenantMembers, LevelReadWrite)},
		},
	}
	if got := aclResolve(t, f, aclMember("alice"), "program"); got != LevelReadWrite {
		t.Fatalf("human member = %q, want read_write", got)
	}
	// The agent is ALSO a tenant member (DexID copies memberships), so the
	// member class still admits it. "Allow no agents" therefore needs the
	// entry to name a group or persons, not the member class — recording the
	// real semantics rather than the hoped-for one.
	if got := aclResolve(t, f, aclAgentOf("agent-7", "alice"), "program"); got != LevelReadWrite {
		t.Fatalf("agent under the member class = %q, want read_write", got)
	}
	// Listed-agents posture: break + person entries, no classes.
	f2 := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelAdmin)},
		},
	}
	if got := aclResolve(t, f2, aclAgentOf("agent-9", "alice"), "program"); got != LevelNone {
		t.Fatalf("unlisted agent = %q, want none", got)
	}
}

// ─── the two conjuncts outside the algebra ───────────────────────────────

func TestAnAgentNeverExceedsItsOwner(t *testing.T) {
	// effective(agent) = evaluate(agent) ∩ evaluate(owner), decision
	// 0bfcd559 [1/12]. An entry naming an agent on a node its owner cannot
	// reach grants NOTHING.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "agent-7", LevelAdmin)},
		},
	}
	if got := aclResolve(t, f, aclAgentOf("agent-7", "alice"), "program"); got != LevelNone {
		t.Fatalf("agent above its owner = %q, want none", got)
	}
	// Grant the owner read, and the agent's admin entry caps to read.
	f.entries["program"] = append(f.entries["program"],
		aclEntryOf("e2", "program", PrincipalPerson, "alice", LevelRead))
	if got := aclResolve(t, f, aclAgentOf("agent-7", "alice"), "program"); got != LevelRead {
		t.Fatalf("agent capped by owner = %q, want read", got)
	}
}

func TestRevokingTheOwnerImmediatelyNarrowsTheAgent(t *testing.T) {
	// Recomputed per request, so there is no cache to invalidate: this is the
	// revocation story Andrew's ruling requires.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	entries := map[string][]ACLEntry{"program": {
		aclEntryOf("e1", "program", PrincipalPerson, "agent-7", LevelAdmin),
		aclEntryOf("e2", "program", PrincipalPerson, "alice", LevelAdmin),
	}}
	f := &fakeACLStore{presence: true, nodes: nodes, entries: entries}
	if got := aclResolve(t, f, aclAgentOf("agent-7", "alice"), "program"); got != LevelAdmin {
		t.Fatalf("before revocation = %q, want admin", got)
	}
	// Tombstone the owner's entry — the store simply stops returning it.
	f.entries["program"] = entries["program"][:1]
	if got := aclResolve(t, f, aclAgentOf("agent-7", "alice"), "program"); got != LevelNone {
		t.Fatalf("after the owner's grant was revoked = %q, want none", got)
	}
}

func TestTheTenantOwnerFloorSurvivesEveryBreak(t *testing.T) {
	// "a branch break can never lock the tenant's owner out" — the
	// unrecoverable-state prevention of decision ccf3266a [2/12].
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{presence: true, nodes: nodes, entries: map[string][]ACLEntry{}}
	g, err := NewACLResolver(f).ExplainEffective(context.Background(), aclTenantAdmin("owner"), testTenant, "program")
	if err != nil {
		t.Fatal(err)
	}
	if g.Level != LevelAdmin {
		t.Fatalf("tenant admin on a broken branch = %q, want admin", g.Level)
	}
	if g.Via != ViaTenantOwnerFloor {
		t.Fatalf("floor reached via %q, want %q — it is a DISTINCT audit reason", g.Via, ViaTenantOwnerFloor)
	}
}

func TestACrossTenantPrincipalCapsAtComment(t *testing.T) {
	// v1 ceiling (decision ccf3266a [2/12]), enforced at RESOLVE time as well
	// as by the schema CHECK. Two independent facts beat one: this binds even
	// if a row's cross-tenant flag was written wrong.
	f := &fakeACLStore{
		presence: true, nodes: aclTree(),
		entries: map[string][]ACLEntry{
			"portfolio": {aclEntryOf("e1", "portfolio", PrincipalPerson, "guest", LevelAdmin)},
		},
	}
	g, err := NewACLResolver(f).ExplainEffective(context.Background(), aclOutsider("guest"), testTenant, "project")
	if err != nil {
		t.Fatal(err)
	}
	if g.Level != LevelComment {
		t.Fatalf("cross-tenant admin entry = %q, want comment", g.Level)
	}
	if !g.CappedCrossTenant {
		t.Fatal("the cross-tenant cap fired without saying so")
	}
	// A MEMBER with the same entry is not capped.
	if got := aclResolve(t, f, aclMember("guest"), "project"); got != LevelAdmin {
		t.Fatalf("member with an admin entry = %q, want admin", got)
	}
}

// ─── the formula of decision 67c69f0f [12/12] ────────────────────────────

func TestReadableIsMemberPathOREntryPath(t *testing.T) {
	// NOT "tenant membership ∩ branch authz". Entries both NARROW members
	// (via a break) and EXTEND to named outsiders. Both directions in one
	// test, because the naive reading of the sketch gets exactly this wrong.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "guest", LevelComment)},
		},
	}
	// Entry path: a NON-member reaches a node.
	if got := aclResolve(t, f, aclOutsider("guest"), "program"); got != LevelComment {
		t.Fatalf("entry path for an outsider = %q, want comment", got)
	}
	// Member path narrowed: a MEMBER does not, on the same node.
	if got := aclResolve(t, f, aclMember("bob"), "program"); got != LevelNone {
		t.Fatalf("member path under a break = %q, want none", got)
	}
	// Member path intact elsewhere.
	if got := aclResolve(t, f, aclMember("bob"), "portfolio"); got != LevelAdmin {
		t.Fatalf("member path on an untouched node = %q, want the default", got)
	}
}

func TestTheAgentCapBindsOnTheEntryPathToo(t *testing.T) {
	// Ratified in Director review 5bfb6df4 item 1: the cap binds on BOTH
	// paths, not only where membership admits.
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "agent-7", LevelComment)},
		},
	}
	a := aclAgentOf("agent-7", "outside-owner")
	a.Tenants = nil // neither agent nor owner is a member here
	if got := aclResolve(t, f, a, "program"); got != LevelNone {
		t.Fatalf("agent reached via the entry path above its owner = %q, want none", got)
	}
}
