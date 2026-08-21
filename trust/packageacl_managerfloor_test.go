package trust

import (
	"context"
	"testing"
)

// THE PACKAGE-MANAGER FLOOR (Director ruling 09ee1bb3 on nw#3059).
//
// A package's NAMED MANAGER holds admin on it implicitly, as a userset
// relation the resolver evaluates — never as an ACL row. This file is the
// pin: every property the ruling names is one subtest, and each one fails
// for a different reason if the floor is implemented in the wrong place.
//
// The three places it could have gone, and why only one of them is right:
//
//   - AS A WRITTEN ENTRY, materialised when a manager is named. Rejected by
//     the ruling itself. It would have to be rewritten every time the manager
//     changes, it would show on a permissions page as a grant somebody made
//     when nobody did, and a revoke of it would produce a manager who manages
//     a package they cannot see.
//   - APPLIED LAST, like the tenant-owner floor, beating every break. Then a
//     portfolio manager would hold admin on a project underneath them that had
//     explicitly broken inheritance — the opposite of what breaking it means.
//     TestABreakBelowTheManagedNodeCutsTheFloor is what fails.
//   - INSIDE direct(node), which is where it is. Absolute on the managed node
//     (a node's own direct grants are never cut by its own inherit flag),
//     inherited downward like any grant, and cut by a break below it.

// aclManagedTree is aclTree with a manager named on the PROGRAM — one rung
// above the leaf, so "and its descendants" is actually exercised rather than
// assumed.
func aclManagedTree() map[string]NodeACL {
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"},
		Inherit: true, ManagerID: "morgan"}
	return nodes
}

// aclLockedOutTree is the case the floor exists for: an administrator has
// broken inheritance at the PROGRAM the manager runs and granted somebody
// else, so nothing above reaches the manager and no entry names them.
func aclLockedOutTree() map[string]NodeACL {
	nodes := aclManagedTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"},
		Inherit: false, ManagerID: "morgan"}
	// The ROOT is sealed too, for the reason aclSealedTree exists: on an
	// unbroken tree every tenant MEMBER already resolves to admin through the
	// implicit tenant-root default, which masks the floor completely and
	// would make each assertion below pass for the wrong reason. And project
	// has TWO parents, so program2 is sealed as well — otherwise the diamond
	// hands the leaf that same default and the descendant test measures
	// nothing.
	nodes["portfolio"] = NodeACL{NodeID: "portfolio", Inherit: false}
	nodes["program2"] = NodeACL{NodeID: "program2", ParentIDs: []string{"portfolio"}, Inherit: false}
	return nodes
}

func TestAManagerIsNotLockedOutOfTheirOwnPackage(t *testing.T) {
	// THE RULING'S CASE, stated as the thing that must not happen. Somebody
	// with tenant admin breaks inheritance on the program and grants it to
	// one other person. The manager is named nowhere, inherits nothing, and
	// must still hold admin — for the same reason an operating system gives
	// an object's owner full control.
	f := &fakeACLStore{
		presence: true, nodes: aclLockedOutTree(),
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "somebody-else", LevelAdmin)},
		},
	}
	if got := aclResolve(t, f, aclMember("morgan"), "program"); got != LevelAdmin {
		t.Errorf("the package's named manager resolves %q on a branch somebody else sealed, want %q.\n"+
			"    A restriction the manager did not set has locked the manager out of the package "+
			"they are accountable for, with no error and no route back.", got, LevelAdmin)
	}
	// And the person who is NOT the manager still gets only what the entry
	// says — the floor must not have widened the branch for everybody.
	if got := aclResolve(t, f, aclMember("stranger"), "program"); got != LevelNone {
		t.Errorf("a non-manager member resolves %q on the sealed branch, want %q — "+
			"the floor is a grant to ONE person, not an opening of the node", got, LevelNone)
	}
}

func TestTheManagerFloorReachesDescendantsThroughInheritance(t *testing.T) {
	// "That package AND ITS DESCENDANTS", and the mechanism is the ordinary
	// one: the floor is part of direct(program), so project inherits it.
	f := &fakeACLStore{presence: true, nodes: aclLockedOutTree(),
		entries: map[string][]ACLEntry{}}
	if got := aclResolve(t, f, aclMember("morgan"), "project"); got != LevelAdmin {
		t.Errorf("the manager of program resolves %q on the project inside it, want %q",
			got, LevelAdmin)
	}
	if got := aclResolve(t, f, aclMember("morgan"), "portfolio"); got != LevelNone {
		t.Errorf("the manager of program resolves %q on the portfolio ABOVE it, want %q — "+
			"a floor that flowed upward would make managing a leaf grant the whole tree",
			got, LevelNone)
	}
}

func TestABreakBelowTheManagedNodeCutsTheFloor(t *testing.T) {
	// The property that distinguishes this floor from the tenant-owner one,
	// and the reason it lives in direct() rather than being applied last.
	//
	// A project inside the managed program breaks inheritance. It keeps its
	// OWN manager's floor if it has one and stops taking the program
	// manager's — because that is what breaking inheritance was asked to do,
	// and a floor that survived it would make "private planning, only me and
	// the people I name" (nw#2291) unexpressible under any manager.
	nodes := aclLockedOutTree()
	nodes["project"] = NodeACL{NodeID: "project", ParentIDs: []string{"program", "program2"},
		Inherit: false}
	f := &fakeACLStore{presence: true, nodes: nodes, entries: map[string][]ACLEntry{}}

	if got := aclResolve(t, f, aclMember("morgan"), "project"); got != LevelNone {
		t.Errorf("the program's manager resolves %q on a project that BROKE inheritance, want %q.\n"+
			"    The floor is being applied as an override instead of as part of direct(node); "+
			"as an override it defeats every break underneath a manager.", got, LevelNone)
	}
	if got := aclResolve(t, f, aclMember("morgan"), "program"); got != LevelAdmin {
		t.Errorf("the manager resolves %q on the node they MANAGE, want %q — "+
			"the break is below them and must not reach back up", got, LevelAdmin)
	}
}

func TestTheManagerFloorIsAUsersetRelationAndNotAnEntry(t *testing.T) {
	// It must be visible as its OWN reason. "Why can Morgan see this" has to
	// answer "they manage it", not "an entry" — because there is no entry to
	// point at, and an answer naming a SourceEntryID that does not exist is
	// worse than no answer.
	f := &fakeACLStore{presence: true, nodes: aclLockedOutTree(),
		entries: map[string][]ACLEntry{}}
	g, err := NewACLResolver(f).ExplainEffective(context.Background(),
		aclMember("morgan"), testTenant, "program")
	if err != nil {
		t.Fatal(err)
	}
	if g.Via != ViaPackageManagerFloor {
		t.Errorf("Via = %q, want %q", g.Via, ViaPackageManagerFloor)
	}
	if g.SourceEntryID != "" {
		t.Errorf("SourceEntryID = %q; the floor is a userset relation and names no row, "+
			"so an audit line pointing at one would point at nothing", g.SourceEntryID)
	}
	if g.SourceNodeID != "program" {
		t.Errorf("SourceNodeID = %q, want %q — the chain must name where the floor is held",
			g.SourceNodeID, "program")
	}
}

func TestTheManagerFloorDoesNotReachACrossTenantGuest(t *testing.T) {
	// A guest from another tenant named as a manager is still a guest. Two
	// reasons, one of them structural: accountability is something a member
	// of the tenant holds, AND without this the unrestricted short-circuit
	// (which cannot see node facts) would disagree with the full walk for
	// exactly this caller. If you relax this, relax the short-circuit too or
	// TestShortCircuitAgreesWithTheFullPath starts lying.
	f := &fakeACLStore{presence: true, nodes: aclLockedOutTree(),
		entries: map[string][]ACLEntry{}}
	if got := aclResolve(t, f, aclOutsider("morgan"), "program"); got != LevelNone {
		t.Errorf("a cross-tenant guest named as manager resolves %q, want %q — "+
			"grant a guest explicitly, so the grant is visible on a permissions page",
			got, LevelNone)
	}
}

func TestTheManagerFloorDoesNotFlowToTheManagersAgent(t *testing.T) {
	// WRITTEN THE OTHER WAY ROUND FROM WHAT I FIRST ASSUMED, and the
	// correction is the useful part, so it is recorded here rather than
	// silently fixed.
	//
	// I expected an agent of the manager to inherit the floor through
	// min(agent, owner). It does not, and it SHOULD not, because the floor is
	// a userset relation on the PERSON — exactly like a person entry naming
	// that person. TestTheAgentPostureOfNW3051IsPureData already pins the
	// same fact for entries: an agent whose owner holds a person entry on a
	// sealed branch resolves none, because the entry names the human and the
	// agent's principal set carries the agent's own id. An agent reaches a
	// branch through the all_agents_of_members class or through an entry
	// naming it, and the cap can only ever LOWER what it found.
	//
	// So this test asserts consistency with the ruled agent model, and it is
	// the test that fails if somebody "fixes" the floor by expanding the
	// manager into their agents — which would give every agent of every
	// manager admin on branches an administrator had deliberately sealed.
	f := &fakeACLStore{presence: true, nodes: aclLockedOutTree(),
		entries: map[string][]ACLEntry{}}
	if got := aclResolve(t, f, aclAgentOf("agent-7", "morgan"), "program"); got != LevelNone {
		t.Errorf("an agent acting for the manager resolves %q on a sealed branch, want %q — "+
			"the floor names a person, and agents are admitted by the agent class or by "+
			"their own entry, never by being owned by somebody who is admitted", got, LevelNone)
	}
	// The manager themselves is unaffected — proving the sealed branch is not
	// simply refusing everybody.
	if got := aclResolve(t, f, aclMember("morgan"), "program"); got != LevelAdmin {
		t.Errorf("the manager resolves %q, want %q", got, LevelAdmin)
	}
}

func TestTheManagerFloorIsInTheReadableSet(t *testing.T) {
	// The list face has to agree with the single-node face, or a manager
	// reaches their package by id and cannot find it in any list — the
	// half-visible state that reads as data loss.
	f := &fakeACLStore{presence: true, nodes: aclLockedOutTree(),
		entries: map[string][]ACLEntry{}}
	set, err := NewACLResolver(f).ReadableSetFor(context.Background(), aclMember("morgan"), testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if set.All {
		t.Fatal("a restricted tenant resolved to ALL")
	}
	want := map[string]bool{"program": true, "project": true}
	got := map[string]bool{}
	for _, id := range set.IDs {
		got[id] = true
	}
	for id := range want {
		if !got[id] {
			t.Errorf("readable set %v omits %q, which the manager holds admin on", set.IDs, id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("readable set contained %q, which the manager floor does not reach", id)
		}
	}
}

func TestANodeWithNoManagerGrantsNobodyTheFloor(t *testing.T) {
	// The empty-string case, which is what every package carries until
	// somebody names a manager: queries.Package initialises manager_id to ''.
	// A floor keyed on the empty id would hand admin to every caller whose
	// principal set happened to contain an empty person key.
	nodes := aclSealedTree()
	f := &fakeACLStore{presence: true, nodes: nodes, entries: map[string][]ACLEntry{}}
	if got := aclResolve(t, f, aclMember(""), "portfolio"); got != LevelNone {
		t.Errorf("a caller with an empty person id resolves %q on an unmanaged node, want %q",
			got, LevelNone)
	}
}
