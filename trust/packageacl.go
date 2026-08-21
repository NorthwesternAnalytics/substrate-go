package trust

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// packageacl.go is the BRANCH ACL vocabulary: levels, principals, entries and
// the one interface an app implements to feed the evaluator. The evaluator
// itself is packageacl_resolver.go; the Requirement is
// packageacl_requirement.go.
//
// Feature nw#3054, INC-1 story nw#3058. The build contract is the accepted
// INC-0 decision record on nw#3055 — every rule in this file cites the
// decision that ruled it, because an authorization evaluator nobody can trace
// back to a ruling is one nobody can safely change.
//
// # Why this lives in substrate rather than in iDEX
//
// Decision f3774718 [9/12 PLACEMENT], which is the architecture doctrine's
// placement rule applied: two or more apps need this, so the MECHANISM is a
// substrate package. iDEX needs it now; Dev Studio, EigenveXtor/Fleet
// Command and the MCP server need it next. What each app owns is its own
// FACTS — where its packages live, what the ancestor chains are, which rows
// exist — supplied through PackageACLStore, exactly as scope.go's scopeSource
// supplies subtree facts today. The trust kit guarantees those facts mean the
// same thing in every product; a substrate-owned central ACL store would
// force every product's hierarchy into one database and recreate the
// second-copy problem 0041 already taught us to avoid.
//
// # The algebra, in four lines
//
// An entry is the tuple node#role@principal (decision 84a088d2 [0/12] —
// Zanzibar relation-tuple/userset-rewrite semantics, implemented in-house).
//
//	effective(node) = direct(node) ∪ [ if inherit(node):
//	                     ∪ over every CONTAINS-parent p of node: effective(p) ]
//
// Principals expand: a group to its members, a virtual class to tenant
// membership. Roles imply along one chain: admin ⊃ read_write ⊃ comment ⊃
// read. "Inheritance broken" is inherit(node) = false, i.e. the parent term
// drops out. That is the WHOLE evaluator. Anything not expressible in it is
// out of scope by design, and that is what keeps the negative-test list
// enumerable.
//
// Two conjuncts sit OUTSIDE the entry algebra and are unaffected by breaks:
// the tenant-owner FLOOR (decision ccf3266a [2/12]) and the agent CAP
// (decision 0bfcd559 [1/12]). They are applied by the resolver, never stored.

// ─── levels ──────────────────────────────────────────────────────────────

// Level is one rung of the role chain: read ⊂ comment ⊂ read_write ⊂ admin
// (decision ccf3266a [2/12]).
//
// ORDERED rather than a set of independent permission bits, and that choice
// is load-bearing in three places at once: the evaluator becomes a max(), the
// permissions UI becomes a radio button instead of a matrix, and the negative
// test list stays enumerable. Windows-style granular masks (13+ bits) were
// rejected for exactly the combinatorial reason.
//
// The verb families each level admits are the exhaustive table in ccf3266a.
// That table is EXHAUSTIVE BY RULE, not by hope: a route or MCP verb that
// ships without a row in it fails a test (Director addition, review 5bfb6df4;
// the table and its test live app-side, where the routes are).
type Level string

const (
	// LevelNone is the ABSENCE of access, and it is deliberately NOT a
	// grantable role.
	//
	// Read that twice, because it is the single most important sentence in
	// this file. There are NO DENY ENTRIES in this model (decisions 84a088d2
	// and 3d9b9b88): the schema's role column has four positive values and no
	// negative one, and narrowing is always break-inheritance-plus-explicit-
	// grants. This constant exists because effective() has to be able to
	// answer "nothing" — it never exists because somebody may write it down.
	// Grantable() and ParseGrantableLevel() both refuse it, and the database
	// CHECK refuses it independently.
	LevelNone Level = "none"

	// LevelRead — list/search issues and packages, get-by-id, journals,
	// relationships (both-ends rule), filtered container reads, filtered
	// export/manifest, gates and readiness, redacted ancestry, external-id
	// resolve.
	LevelRead Level = "read"

	// LevelComment — read, plus discussion/comment create and edit-own. This
	// tier exists because the guest model already promised it (nw#1169's
	// viewer|commenter), and it is the cap for cross-tenant principals in v1.
	LevelComment Level = "comment"

	// LevelReadWrite — comment, plus item create/update, status transitions,
	// journal append, relationship create/delete, sprint/backlog membership,
	// ranks, estimates, tags, and assignment.
	LevelReadWrite Level = "read_write"

	// LevelAdmin — read_write, plus the ACL entries and inherit flag on the
	// node, security-group editing scoped to groups used on nodes they
	// administer, package settings, container lifecycle, item delete, and
	// moving or re-homing packages.
	LevelAdmin Level = "admin"
)

// levelRank orders the chain. LevelNone is rank 0 and every grantable level
// is above it, so AtLeast is one integer comparison rather than a switch
// repeated at every enforcement point.
var levelRank = map[Level]int{
	LevelNone:      0,
	LevelRead:      1,
	LevelComment:   2,
	LevelReadWrite: 3,
	LevelAdmin:     4,
}

// GrantableLevels is the four roles the schema's CHECK constraint accepts, in
// ascending order. LevelNone is absent, and its absence is the enforcement.
var GrantableLevels = []Level{LevelRead, LevelComment, LevelReadWrite, LevelAdmin}

// AtLeast reports whether l meets or exceeds min.
//
// An UNKNOWN level ranks 0 and therefore satisfies nothing. That is the
// fail-closed direction: a level that arrived from a future schema version,
// or from a typo, must refuse rather than admit.
func (l Level) AtLeast(min Level) bool { return levelRank[l] >= levelRank[min] }

// Grantable reports whether l is one of the four roles that may be written
// into an entry. LevelNone is not.
func (l Level) Grantable() bool {
	for _, g := range GrantableLevels {
		if l == g {
			return true
		}
	}
	return false
}

// Min returns the lower of two levels — the agent cap's operator (decision
// 0bfcd559 [1/12]: effective(agent) = evaluate(agent) ∩ evaluate(owner), and
// on a totally ordered chain intersection IS the minimum).
func Min(a, b Level) Level {
	if levelRank[a] <= levelRank[b] {
		return a
	}
	return b
}

// Max returns the higher of two levels — the union operator the whole
// evaluator is built from: entries on a node union, and a node with several
// CONTAINS-parents unions their effective sets (decision 3d9b9b88 [4/12]).
func Max(a, b Level) Level {
	if levelRank[a] >= levelRank[b] {
		return a
	}
	return b
}

// ParseGrantableLevel converts wire text into a Level a caller may actually
// grant, refusing anything else.
//
// It refuses "none" BY NAME rather than falling through to the generic error,
// because "none" is the one wrong answer somebody will genuinely try: it is
// what the legacy per-package model (migration 0051, superseded by Director
// ruling 278ead22) called a deny, and an API that answered "unknown level"
// would leave the caller guessing at spelling rather than learning that the
// concept is gone.
func ParseGrantableLevel(s string) (Level, error) {
	l := Level(strings.TrimSpace(s))
	if l.Grantable() {
		return l, nil
	}
	if l == LevelNone {
		return "", fmt.Errorf(
			"%q is not a grantable role: this model has no deny entries — "+
				"narrow a branch by breaking inheritance and granting explicitly", s)
	}
	return "", fmt.Errorf("%q is not a role; use one of read, comment, read_write, admin", s)
}

// ─── principals ──────────────────────────────────────────────────────────

// PrincipalKind is what an entry's principal_id names (decision 0bfcd559
// [1/12]).
type PrincipalKind string

const (
	// PrincipalPerson is a DexID person id, and it covers HUMANS AND AGENTS
	// ALIKE.
	//
	// There is deliberately no agent kind. "The team member is an agent" is
	// Andrew's framing, and a separate kind would re-introduce the special
	// case the ruling forbids and double every query. What makes an agent an
	// agent, here, is the CAP the resolver applies — never a different row
	// shape.
	PrincipalPerson PrincipalKind = "person"
	// PrincipalGroup is a tenant-scoped security group id. Groups are how a
	// branch is granted to a team without one row per person. No nesting in
	// v1.
	PrincipalGroup PrincipalKind = "group"
	// PrincipalClass is one of the two virtual classes below.
	PrincipalClass PrincipalKind = "class"
)

const (
	// ClassAllTenantMembers expands, at resolve time, to every member of the
	// entry's tenant.
	//
	// This class is what makes the agent postures of nw#3051 pure data rather
	// than a second mechanism: "allow all agents" is the default unrestricted
	// mode (no entries at all); "allow no agents" on a branch is break +
	// an entry for this class and none for the agent class; "allow listed
	// agents" is break + this class + person entries for the named agents.
	ClassAllTenantMembers = "all_tenant_members"
	// ClassAllAgentsOfMembers expands to every agent acting for a member of
	// the entry's tenant. It is only ever ADDITIVE — an agent still cannot
	// exceed its owner, because the cap is a conjunct outside this algebra.
	ClassAllAgentsOfMembers = "all_agents_of_members"
)

// VirtualClasses is the closed vocabulary the schema's CHECK also enforces.
// Kept in step deliberately: a class id that the database accepts and this
// package does not know would be an entry that silently matches nobody — a
// grant that looks made and is not.
var VirtualClasses = []string{ClassAllTenantMembers, ClassAllAgentsOfMembers}

// ValidClass reports whether id is one of the two virtual classes.
func ValidClass(id string) bool {
	for _, c := range VirtualClasses {
		if c == id {
			return true
		}
	}
	return false
}

// principalKey is how a principal is matched during evaluation: kind and id
// together, so a group id can never accidentally match a person id.
func principalKey(kind PrincipalKind, id string) string { return string(kind) + ":" + id }

// ─── the facts an app supplies ───────────────────────────────────────────

// ACLEntry is one live tuple, as the app reads it out of its own storage.
//
// A REVOKED entry never reaches this struct. Revocation is a tombstone in the
// app's table (never a delete, so "who could reach this branch last March"
// stays answerable), and every store read filters it out. The evaluator has
// no concept of a revoked entry, which is exactly the point: there is one
// place that decides whether a row is live, and it is not here.
type ACLEntry struct {
	// ID is the app's row id, carried so a transpose answer can point at the
	// exact grant that admits somebody.
	ID string
	// NodeID is the package this entry sits on.
	NodeID string
	// PrincipalKind and PrincipalID name who is granted.
	PrincipalKind PrincipalKind
	PrincipalID   string
	// Role is the level granted. Always one of GrantableLevels: the schema
	// CHECK guarantees it, and the evaluator treats anything else as rank 0.
	Role Level
}

// NodeACL is one package node's structural facts: who its CONTAINS-parents
// are, and whether it inherits from them.
type NodeACL struct {
	NodeID string
	// ParentIDs is EVERY CONTAINS-parent, not a primary one.
	//
	// Diamonds are real in this graph and the ruling is union over all
	// parents (decision 3d9b9b88 [4/12]). The two rejected alternatives are
	// worth naming here because both look reasonable: primary-parent-only
	// invents a "primary" edge property that does not exist and makes access
	// depend on which edge happened to be drawn first; INTERSECTION would
	// mean linking a node into a second, more restricted parent silently
	// REVOKES access — a write to the graph revoking access as a side effect,
	// invisible on any permissions page. Union is monotone: linking a node
	// never narrows anyone.
	//
	// Empty means this node is a root of the tenant's containment graph. The
	// resolver treats the tenant itself as the parent of every root — see
	// implicitRootLevel in the resolver.
	ParentIDs []string
	// Inherit is the node's inherit flag. ABSENCE OF A SETTING ROW MEANS
	// TRUE, and the store adapter is responsible for having already applied
	// that: a NodeACL arriving here always states an opinion, because a
	// three-valued flag would give every caller of this struct a chance to
	// get the default wrong in its own way.
	Inherit bool
	// ManagerID is the person id of this node's NAMED MANAGER, or empty.
	//
	// It is a FACT the app reports, exactly like ParentIDs — who manages a
	// package is the app's own record — and the resolver turns it into a
	// grant. That split is the same one the whole seam is built on: the app
	// may report facts, only trust may decide outcomes. See the manager
	// floor in packageacl_resolver.go for what the resolver does with it and
	// why it is not an entry.
	ManagerID string
}

// PackageACLStore is the app-side seam: the four facts the evaluator needs
// and cannot know.
//
// Implementations live in the CONSUMING APP (see
// services/api/internal/graph/queries/package_acl.go in iDEX), which is the
// deliberate inverse of the Requirement interface's rule. A Requirement
// decides a security OUTCOME, so no app may implement one. A store reports
// FACTS about an app's own rows, which only that app can know. Getting a fact
// wrong is a bug the app's own tests catch; getting an outcome wrong is a
// disclosure bug nobody catches for years.
//
// Every method takes a tenantID and every implementation MUST scope its reads
// by it. The evaluator never re-checks: a store that leaked another tenant's
// rows would have leaked them before this package saw them.
type PackageACLStore interface {
	// AncestorChains returns nodeIDs together with the TRANSITIVE CLOSURE of
	// their CONTAINS-ancestors, each carrying its parents and its resolved
	// inherit flag.
	//
	// The closure, not one hop: the evaluator recurses in memory and must not
	// go back to the database per rung. Package trees are ≤4 deep and small
	// (hundreds of nodes), so the closure is cheap and the alternative — a
	// query per hop per request — is the graph-cost mistake architecture
	// doctrine says is never to be assumed away.
	//
	// A NIL OR EMPTY nodeIDs MEANS THE WHOLE TENANT'S TREE. That is what
	// ReadableSet asks for on a restricted tenant, and it is why this
	// interface stays at four methods instead of five.
	AncestorChains(ctx context.Context, tenantID string, nodeIDs []string) (map[string]NodeACL, error)

	// EntriesFor returns the LIVE entries on each of nodeIDs, keyed by node
	// id. Nodes with no entries may be absent from the map or present with an
	// empty slice; both mean the same thing.
	EntriesFor(ctx context.Context, tenantID string, nodeIDs []string) (map[string][]ACLEntry, error)

	// GroupMemberships returns, for each person id, the security groups they
	// are a live member of in this tenant.
	//
	// Takes a SLICE because the agent cap needs two answers at once — the
	// agent's groups and its owner's — and two round trips for one request's
	// decision is a cost with no reason.
	GroupMemberships(ctx context.Context, tenantID string, personIDs []string) (map[string][]string, error)

	// TenantACLPresence reports whether this tenant has ANY ACL rows at all.
	//
	// THE SHIP-DAY GUARANTEE RIDES ON THIS ONE BOOLEAN (decision cf03d84d
	// [5/12] with c8f0cd3d [8/12]). False means the tenant is unrestricted,
	// the resolver short-circuits to ALL, and every query is byte-identical
	// to what it was before this feature existed. It is one cached existence
	// check per request — proof P4's "at most one extra query on the
	// unrestricted path".
	//
	// IT MUST COUNT THE LEGACY MODEL TOO. Director ruling 278ead22 on
	// nw#3058: the branch ACL supersedes public.package_permission, and until
	// that table is retired (nw#3064, INC-2) an implementation must count its
	// rows alongside package_acl_entry and package_acl_setting. Otherwise a
	// tenant the OLD model already restricts is reported unrestricted, and
	// the short-circuit resolves it to ALL — a false negative sitting
	// directly underneath INC-2's enforcement.
	TenantACLPresence(ctx context.Context, tenantID string) (bool, error)
}

// sortedKeys is a small helper the resolver and its tests both use: map
// iteration order is random in Go, and an authorization answer that changes
// order between requests is one nobody can diff. Every set this package
// returns is sorted.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
