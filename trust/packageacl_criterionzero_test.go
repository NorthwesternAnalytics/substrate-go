package trust

import (
	"context"
	"testing"
)

// CRITERION ZERO, at the substrate layer.
//
// Decision c8f0cd3d [8/12] proves "default unchanged" four ways. Two of them
// are properties of THIS package and are asserted here: P2 (the short-circuit
// assertion, made through the resolver's public API rather than by peeking at
// SQL, so it proves the code path the fleet will actually take) and P4 (cost,
// asserted by counting store calls so "unchanged" covers latency class and
// not just bytes). P1 is a migration assertion and P3 is the golden-probe
// differential; both live app-side, where the database and the roster are.
//
// The most important test in this file is the last one. A short-circuit that
// quietly DISAGREES with the path it is short-circuiting is how a feature
// that "changed nothing" changes something, and no amount of code review
// finds it.

func TestP2UnrestrictedTenantResolvesToALL(t *testing.T) {
	f := &fakeACLStore{presence: false, nodes: aclTree()}
	r := NewACLResolver(f)

	set, err := r.ReadableSetFor(context.Background(), aclMember("alice"), testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if !set.All {
		t.Fatalf("unrestricted tenant resolved to %v, want ALL", set)
	}
	// ALL means "impose no narrowing", so it must be true of a package the
	// resolver has never even heard of — the query keeps its existing tenant
	// predicate and gains nothing.
	if !set.Contains("a-package-nobody-mentioned") {
		t.Fatal("ALL did not contain an arbitrary package")
	}
}

func TestP2EveryPackageResolvesToTheMemberDefaultOnShipDay(t *testing.T) {
	// Ship day: zero rows in all three tables. Every member must resolve to
	// exactly the authority they had the day before this package existed,
	// which the legacy model (migration 0051) spelled as FULL for a package
	// with no grant anywhere on its path. Director ruling 278ead22 fixes the
	// new model's equivalent at the implicit tenant-root admin grant.
	f := &fakeACLStore{presence: false, nodes: aclTree()}
	r := NewACLResolver(f)
	for _, node := range []string{"portfolio", "program", "program2", "project"} {
		lvl, err := r.Effective(context.Background(), aclMember("alice"), testTenant, node)
		if err != nil {
			t.Fatal(err)
		}
		if lvl != LevelAdmin {
			t.Fatalf("%s = %q on ship day, want admin (the unchanged default)", node, lvl)
		}
	}
	// An agent of that member is unchanged too — which is the half that
	// matters most, because a regression here breaks every lane at once.
	for _, node := range []string{"portfolio", "project"} {
		lvl, err := r.Effective(context.Background(), aclAgentOf("agent-7", "alice"), testTenant, node)
		if err != nil {
			t.Fatal(err)
		}
		if lvl != LevelAdmin {
			t.Fatalf("agent on %s = %q on ship day, want admin", node, lvl)
		}
	}
	// A NON-member is unchanged too: nothing, exactly as tenant isolation
	// already answered.
	if lvl, _ := r.Effective(context.Background(), aclOutsider("stranger"), testTenant, "project"); lvl != LevelNone {
		t.Fatalf("outsider on ship day = %q, want none", lvl)
	}
}

func TestP4TheUnrestrictedPathCostsONEExistenceCheck(t *testing.T) {
	// "at most ONE cached existence check per request", and cached means the
	// second question is free. Counted, not asserted in prose.
	f := &fakeACLStore{presence: false, nodes: aclTree()}
	r := NewACLResolver(f)
	ctx := context.Background()
	a := aclMember("alice")

	for i := 0; i < 25; i++ {
		if _, err := r.Effective(ctx, a, testTenant, "project"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.ReadableSetFor(ctx, a, testTenant); err != nil {
		t.Fatal(err)
	}

	if f.presenceCalls != 1 {
		t.Errorf("presence checks = %d, want exactly 1 (cached for the request)", f.presenceCalls)
	}
	if f.chainCalls != 0 {
		t.Errorf("ancestor-chain reads = %d, want 0 on the unrestricted path", f.chainCalls)
	}
	if f.entryCalls != 0 {
		t.Errorf("entry reads = %d, want 0 on the unrestricted path", f.entryCalls)
	}
	if f.groupCalls != 0 {
		t.Errorf("group reads = %d, want 0 on the unrestricted path", f.groupCalls)
	}
}

func TestTheRestrictedPathDoesNotQUERYPerNode(t *testing.T) {
	// The cost ruling for a RESTRICTED tenant: one pass over the tenant's
	// tree and rows, evaluated in memory — never a graph walk per package,
	// and never anything per row of the list being filtered.
	f := &fakeACLStore{presence: true, nodes: aclSealedTree(), entries: map[string][]ACLEntry{}}
	r := NewACLResolver(f)
	if _, err := r.ReadableSetFor(context.Background(), aclMember("alice"), testTenant); err != nil {
		t.Fatal(err)
	}
	if f.chainCalls > 1 {
		t.Errorf("ancestor-chain reads = %d for a whole-tenant readable set, want 1", f.chainCalls)
	}
	if f.entryCalls > 2 {
		t.Errorf("entry reads = %d, want at most 2 regardless of node count", f.entryCalls)
	}
}

func TestShortCircuitAgreesWithTheFullPath(t *testing.T) {
	// THE LOAD-BEARING TEST OF THIS FILE.
	//
	// The unrestricted short-circuit is an OPTIMISATION. Its licence is that
	// it returns what the full evaluation would have returned. So: take a
	// tenant with zero rows, resolve every node twice — once with presence
	// false (short-circuit) and once with presence true (full walk over the
	// same, empty, row set) — and require the same answer for every caller
	// kind. If these ever diverge, the short-circuit has become a second
	// evaluator and criterion zero is no longer proven by P2 at all.
	callers := map[string]*Access{
		"member":       aclMember("alice"),
		"tenant admin": aclTenantAdmin("owner"),
		"agent":        aclAgentOf("agent-7", "alice"),
		"outsider":     aclOutsider("stranger"),
	}
	for name, a := range callers {
		for _, node := range []string{"portfolio", "program", "program2", "project"} {
			short, err := NewACLResolver(&fakeACLStore{presence: false, nodes: aclTree()}).
				Effective(context.Background(), a, testTenant, node)
			if err != nil {
				t.Fatal(err)
			}
			full, err := NewACLResolver(&fakeACLStore{presence: true, nodes: aclTree(), entries: map[string][]ACLEntry{}}).
				Effective(context.Background(), a, testTenant, node)
			if err != nil {
				t.Fatal(err)
			}
			if short != full {
				t.Errorf("%s on %s: short-circuit says %q, full evaluation says %q — "+
					"the optimisation has diverged from the algebra", name, node, short, full)
			}
		}
	}
}

// ─── the list face ───────────────────────────────────────────────────────

func TestReadableSetNarrowsToWhatEntriesAdmit(t *testing.T) {
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelRead)},
		},
	}
	set, err := NewACLResolver(f).ReadableSetFor(context.Background(), aclMember("alice"), testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if set.All {
		t.Fatal("a restricted tenant resolved to ALL")
	}
	// program grants read; project inherits from program (and program2, which
	// grants nothing) — union admits it.
	want := map[string]bool{"program": true, "project": true}
	if len(set.IDs) != len(want) {
		t.Fatalf("readable set = %v, want %v", set.IDs, want)
	}
	for _, id := range set.IDs {
		if !want[id] {
			t.Errorf("readable set contained %q, which grants nothing", id)
		}
	}
}

func TestAnEmptyReadableSetIsNeverNil(t *testing.T) {
	// It feeds `WHERE project_id = ANY($1)`, which matches nothing for an
	// empty list — fail-closed by construction rather than by how nil
	// happens to marshal.
	f := &fakeACLStore{presence: true, nodes: aclSealedTree(), entries: map[string][]ACLEntry{}}
	set, err := NewACLResolver(f).ReadableSetFor(context.Background(), aclOutsider("stranger"), testTenant)
	if err != nil {
		t.Fatal(err)
	}
	if set.All {
		t.Fatal("an outsider resolved to ALL")
	}
	if set.IDs == nil {
		t.Fatal("empty readable set was nil rather than an empty slice")
	}
	if len(set.IDs) != 0 {
		t.Fatalf("outsider readable set = %v, want empty", set.IDs)
	}
}

func TestANilCallerReadsNothing(t *testing.T) {
	r := NewACLResolver(&fakeACLStore{presence: false, nodes: aclTree()})
	if lvl, _ := r.Effective(context.Background(), nil, testTenant, "project"); lvl != LevelNone {
		t.Fatalf("nil caller = %q, want none", lvl)
	}
	set, _ := r.ReadableSetFor(context.Background(), nil, testTenant)
	if set.All || len(set.IDs) != 0 {
		t.Fatalf("nil caller readable set = %v, want empty", set)
	}
}

// ─── the transpose ───────────────────────────────────────────────────────

func TestReachingEntriesNamesTheChain(t *testing.T) {
	// "why can X see this" always names a chain (decision 3d9b9b88 [4/12]):
	// the answer must point at the node the grant physically sits on, which
	// may be several rungs above the node asked about.
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"portfolio": {aclEntryOf("e1", "portfolio", PrincipalGroup, "engineering", LevelReadWrite)},
			"project":   {aclEntryOf("e2", "project", PrincipalPerson, "guest", LevelComment)},
		},
	}
	reach, err := NewACLResolver(f).ReachingEntries(context.Background(), testTenant, "project")
	if err != nil {
		t.Fatal(err)
	}
	byPrincipal := map[string]Reach{}
	for _, r := range reach {
		byPrincipal[r.PrincipalID] = r
	}
	eng, ok := byPrincipal["engineering"]
	if !ok {
		t.Fatal("the inherited group grant was not reported")
	}
	if eng.SourceNodeID != "portfolio" || !eng.Inherited {
		t.Fatalf("inherited grant reported as %+v, want source=portfolio inherited=true", eng)
	}
	guest, ok := byPrincipal["guest"]
	if !ok {
		t.Fatal("the direct grant was not reported")
	}
	if guest.SourceNodeID != "project" || guest.Inherited {
		t.Fatalf("direct grant reported as %+v, want source=project inherited=false", guest)
	}
	// Groups and classes are NOT expanded here — that needs a tenant roster,
	// which is an app fact (decision f3774718 [9/12]).
	if eng.PrincipalKind != PrincipalGroup {
		t.Fatalf("the group was expanded inside the substrate: %+v", eng)
	}
}

func TestReachingEntriesStopsAtABreak(t *testing.T) {
	nodes := aclTree()
	nodes["program"] = NodeACL{NodeID: "program", ParentIDs: []string{"portfolio"}, Inherit: false}
	nodes["project"] = NodeACL{NodeID: "project", ParentIDs: []string{"program"}, Inherit: true}
	f := &fakeACLStore{
		presence: true, nodes: nodes,
		entries: map[string][]ACLEntry{
			"portfolio": {aclEntryOf("e1", "portfolio", PrincipalPerson, "alice", LevelAdmin)},
		},
	}
	reach, err := NewACLResolver(f).ReachingEntries(context.Background(), testTenant, "project")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reach {
		if r.PrincipalID == "alice" {
			t.Fatalf("a grant above a break was reported as reaching below it: %+v", r)
		}
	}
}

func TestReachingEntriesReportsTheImplicitDefault(t *testing.T) {
	// A permissions page for an untouched node must show the default that is
	// actually in force. An empty list would read as "nobody", which is the
	// opposite of the truth.
	f := &fakeACLStore{presence: true, nodes: aclTree(), entries: map[string][]ACLEntry{}}
	reach, err := NewACLResolver(f).ReachingEntries(context.Background(), testTenant, "project")
	if err != nil {
		t.Fatal(err)
	}
	if len(reach) != 1 {
		t.Fatalf("untouched node reported %d reaching entries, want 1 (the implicit default)", len(reach))
	}
	if reach[0].PrincipalKind != PrincipalClass || reach[0].PrincipalID != ClassAllTenantMembers {
		t.Fatalf("implicit default reported as %+v", reach[0])
	}
	if reach[0].Role != LevelAdmin {
		t.Fatalf("implicit default level = %q, want admin", reach[0].Role)
	}
}

// ─── the Requirement seam ────────────────────────────────────────────────

func TestRequirePackageAccessRidesTheOrdinaryDecisionPipeline(t *testing.T) {
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelComment)},
		},
	}
	r := NewACLResolver(f)
	a := aclMember("alice")

	req, err := r.RequirePackageAccess(context.Background(), a, testTenant, "program", LevelComment)
	if err != nil {
		t.Fatal(err)
	}
	if d := DecideFor(a, testTenant, req); !d.Allowed() {
		t.Fatalf("comment access refused at the comment threshold: %+v", d)
	}

	req, err = r.RequirePackageAccess(context.Background(), a, testTenant, "program", LevelReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	d := DecideFor(a, testTenant, req)
	if d.Allowed() {
		t.Fatal("comment access satisfied the read_write threshold")
	}
	if d.ReasonCode != ReasonRoleDenied {
		t.Fatalf("reason code = %q, want %q (INC-1 reuses it — see the doc comment)", d.ReasonCode, ReasonRoleDenied)
	}
	if d.HTTPStatus() != 403 {
		t.Fatalf("refusal status = %d, want 403", d.HTTPStatus())
	}
}

func TestNoCredentialFieldAppearsInTheAlgebra(t *testing.T) {
	// Decision 50056838 [11/12], the substrate half: the resolver's inputs
	// are {Access identity/owner/memberships, ACL rows, package chains}. A
	// caller's BEARER TOKEN must make no difference to any answer — if it
	// ever did, "changing what an agent may reach requires touching its key"
	// would have crept back in.
	f := &fakeACLStore{
		presence: true, nodes: aclSealedTree(),
		entries: map[string][]ACLEntry{
			"program": {aclEntryOf("e1", "program", PrincipalPerson, "alice", LevelReadWrite)},
		},
	}
	withToken := aclMember("alice")
	withToken.BearerToken = "a-completely-different-token"
	withoutToken := aclMember("alice")

	a, err := NewACLResolver(f).Effective(context.Background(), withToken, testTenant, "program")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewACLResolver(f).Effective(context.Background(), withoutToken, testTenant, "program")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("the credential changed the answer: %q with a token, %q without", a, b)
	}
}
