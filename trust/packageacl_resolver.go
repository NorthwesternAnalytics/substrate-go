package trust

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// packageacl_resolver.go is THE resolver — singular, deliberately.
//
// Decision cf03d84d [5/12] on nw#3055: ONE resolver, computed once per
// request, request-cached, with two faces. effective(access, nodeID) → Level
// answers single-node verbs; ReadableSet(access) → {ALL | id set} answers
// list predicates by landing in the same ANY($ids) position that the tenant
// narrowing occupies today.
//
// The alternative that was rejected is the one every codebase drifts into by
// accident: per-verb ad-hoc checks written in handlers. That is the
// two-mechanisms drift nw#3050 forbids, and in an authorization layer drift
// surfaces as disclosure bugs — the worst class. If you are about to write a
// permission comparison anywhere else, you are writing the second mechanism.
//
// # Cost, measured rather than hoped
//
// Package trees are ≤4 deep and small. effective() loads one ancestor closure
// plus its entries — two indexed relational reads, memoized for the rest of
// the request. ReadableSet on a restricted tenant is ONE pass over that
// tenant's settings and entries (hundreds of rows at most) evaluated in
// memory against the package tree: never a per-package graph walk, and never
// per-row inside a list query. On an UNRESTRICTED tenant it is one cached
// existence check and nothing else, which is what makes criterion zero true.

// ACLResolver is one request's view of the branch ACL.
//
// CREATE ONE PER REQUEST. Every map on it is a request cache, and that is a
// correctness property, not a performance one: an entry written during a
// request must be visible on the NEXT request (read-after-write in one
// Postgres, no replication lag, no zookies), which is the revocation story
// Andrew's ruling requires — removing somebody from a group ends their
// authorization immediately. A resolver shared across requests would be a
// cache of authorization decisions, and a cache of authorization decisions is
// a permission that outlives its revocation.
//
// It is mutex-guarded because one request may fan out to concurrent handlers,
// not because it is meant to be shared between requests.
type ACLResolver struct {
	store PackageACLStore

	mu       sync.Mutex
	presence map[string]bool                  // tenantID → any ACL rows at all
	nodes    map[string]map[string]NodeACL    // tenantID → nodeID → structure
	entries  map[string]map[string][]ACLEntry // tenantID → nodeID → live entries
	groups   map[string]map[string][]string   // tenantID → personID → group ids
	full     map[string]bool                  // tenantID → whole tree already loaded
	levels   map[string]EffectiveGrant        // memo: tenant|principals-digest|node
}

// NewACLResolver builds a resolver over one app's store. One per request.
func NewACLResolver(store PackageACLStore) *ACLResolver {
	return &ACLResolver{
		store:    store,
		presence: map[string]bool{},
		nodes:    map[string]map[string]NodeACL{},
		entries:  map[string]map[string][]ACLEntry{},
		groups:   map[string]map[string][]string{},
		full:     map[string]bool{},
		levels:   map[string]EffectiveGrant{},
	}
}

// ─── the single-node face ────────────────────────────────────────────────

// Effective answers "what may this caller do on this package".
//
// The order of operations is the contract, and it is not interchangeable:
//
//  1. Nothing for a nil caller. Fail closed before anything else runs.
//  2. The UNRESTRICTED SHORT-CIRCUIT. A tenant with no ACL rows anywhere
//     resolves exactly as it did before this feature existed. This is an
//     optimisation that must AGREE with the long path, never diverge from it
//     — asserted as a test (TestShortCircuitAgreesWithTheFullPath), because a
//     short-circuit that quietly disagrees is how a feature that "changed
//     nothing" changes something.
//  3. THE ENTRY ALGEBRA — union of this node's matching entries with, if the
//     node inherits, the effective set of every CONTAINS-parent. Decision
//     84a088d2 [0/12], and it is the whole of what entries mean.
//  4. THE AGENT CAP: effective(agent) = min(agent, owner). Outside the
//     algebra (decision 0bfcd559 [1/12]) and recomputed per request, so an
//     owner losing access immediately narrows every agent acting for them. An
//     entry naming an agent on a node its owner cannot reach grants nothing.
//  5. THE CROSS-TENANT CAP: a caller who is not a member of this tenant caps
//     at comment in v1 (decision ccf3266a [2/12]). Belt and braces with the
//     schema CHECK, on purpose — two independent facts beat one, and this one
//     binds even if a row's cross-tenant flag was written wrong.
//  6. THE TENANT-OWNER FLOOR, applied LAST so it beats every cap and every
//     break: a tenant owner or admin always resolves admin on every node of
//     their tenant. A branch break can never lock the tenant's own owner out.
//     Windows permits self-lockout and answers it with "take ownership"; we
//     simply never enter the state, which is unrecoverable-state prevention
//     and Prime-Directive-adjacent — the accountable human must always be
//     able to see and repair the record. Reaching a node through the floor
//     rather than through an entry is a distinct audit reason, and callers
//     that audit should ask ExplainEffective rather than infer it.
func (r *ACLResolver) Effective(ctx context.Context, access *Access, tenantID, nodeID string) (Level, error) {
	d, err := r.ExplainEffective(ctx, access, tenantID, nodeID)
	if err != nil {
		return LevelNone, err
	}
	return d.Level, nil
}

// EffectiveGrant is Effective plus WHY, for audit trails and for the
// permissions UI's "why can X see this".
//
// Decision 3d9b9b88 [4/12] requires that the answer to "why can X see this"
// always names a chain, and 446494b5 [7/12] requires every denial to emit a
// server-side audit event. Neither is satisfiable if the resolver returns a
// bare level, so it returns this and Effective is the thin wrapper.
type EffectiveGrant struct {
	// Level is the answer.
	Level Level
	// Via names how the level was reached: "entry", "tenant_owner_floor",
	// "tenant_member_default", "unrestricted", or "" when the answer is
	// LevelNone.
	Via string
	// SourceNodeID is the node carrying the entry that admitted the caller,
	// when Via is "entry". Empty otherwise. This is the "chain" half of "why
	// can X see this": the node named here is where the grant physically is,
	// which may be several rungs above the node asked about.
	SourceNodeID string
	// SourceEntryID is that entry's row id, so an audit line can point at the
	// exact grant rather than at a level.
	SourceEntryID string
	// CappedByOwner reports that the agent cap lowered the answer — the
	// caller is an agent that would have resolved higher on its own. Worth
	// surfacing because it is the one refusal whose remedy is to change the
	// OWNER's access, not the agent's.
	CappedByOwner bool
	// CappedCrossTenant reports that the v1 cross-tenant ceiling lowered the
	// answer.
	CappedCrossTenant bool
}

// ExplainEffective is Effective with its reasoning attached. See
// EffectiveGrant.
func (r *ACLResolver) ExplainEffective(ctx context.Context, access *Access, tenantID, nodeID string) (EffectiveGrant, error) {
	if access == nil || tenantID == "" || nodeID == "" {
		return EffectiveGrant{Level: LevelNone}, nil
	}

	restricted, err := r.restricted(ctx, tenantID)
	if err != nil {
		return EffectiveGrant{Level: LevelNone}, err
	}

	if !restricted {
		// Step 2. No ACL rows anywhere in this tenant. Every member resolves
		// to the pre-feature default and every non-member resolves to
		// nothing, which is precisely what this API did the day before this
		// package existed.
		return r.unrestrictedGrant(access, tenantID), nil
	}

	callerPrincipals, err := r.principalsFor(ctx, access, tenantID, access.PersonID)
	if err != nil {
		return EffectiveGrant{Level: LevelNone}, err
	}
	grant, err := r.walk(ctx, tenantID, nodeID, callerPrincipals)
	if err != nil {
		return EffectiveGrant{Level: LevelNone}, err
	}

	// Step 4 — the agent cap.
	if access.IsAgent && access.OwnerPersonID != "" && access.OwnerPersonID != access.PersonID {
		ownerAccess := *access
		ownerAccess.IsAgent = false
		ownerAccess.PersonID = access.OwnerPersonID
		ownerPrincipals, err := r.principalsFor(ctx, &ownerAccess, tenantID, access.OwnerPersonID)
		if err != nil {
			return EffectiveGrant{Level: LevelNone}, err
		}
		ownerGrant, err := r.walk(ctx, tenantID, nodeID, ownerPrincipals)
		if err != nil {
			return EffectiveGrant{Level: LevelNone}, err
		}
		if ownerIsFloored(&ownerAccess, tenantID) {
			ownerGrant.Level = LevelAdmin
		}
		if capped := Min(grant.Level, ownerGrant.Level); capped != grant.Level {
			grant.Level = capped
			grant.CappedByOwner = true
		}
	}

	// Step 5 — the cross-tenant ceiling.
	if !access.HasTenant(tenantID) {
		if capped := Min(grant.Level, LevelComment); capped != grant.Level {
			grant.Level = capped
			grant.CappedCrossTenant = true
		}
	}

	// Step 6 — the floor, last, beating everything above it.
	if ownerIsFloored(access, tenantID) {
		return EffectiveGrant{Level: LevelAdmin, Via: ViaTenantOwnerFloor}, nil
	}

	if grant.Level == LevelNone {
		grant.Via = ""
		grant.SourceNodeID = ""
		grant.SourceEntryID = ""
	}
	return grant, nil
}

// The Via vocabulary. Constants because audit rows and UI copy both read them,
// and a typo in either would be invisible.
const (
	// ViaEntry — an explicit entry admitted the caller, at SourceNodeID.
	ViaEntry = "entry"
	// ViaTenantOwnerFloor — the tenant owner/admin floor, which no break can
	// cut off. A distinct audit reason by ruling (ccf3266a [2/12]).
	ViaTenantOwnerFloor = "tenant_owner_floor"
	// ViaTenantMemberDefault — the implicit tenant-root grant every member
	// holds until an owner restricts something. See implicitRootLevel.
	ViaTenantMemberDefault = "tenant_member_default"
	// ViaUnrestricted — the tenant has no ACL rows at all, so nothing was
	// evaluated. The ship-day answer for every tenant.
	ViaUnrestricted = "unrestricted"
)

// TenantOwnerRoles are the tenant-membership roles that hold the floor.
//
// The TENANT axis, never the platform axis, and that is the difference
// between a gate that works and one that refuses every agent: DexID copies a
// person's tenant memberships (roles included) onto every agent they enroll,
// but derives platform_roles from the agent's OWN person row, which is never
// granted anything. See Access.PlatformRoles for the full note.
var TenantOwnerRoles = []string{"owner", "admin"}

func ownerIsFloored(a *Access, tenantID string) bool {
	m, ok := a.Membership(tenantID)
	if !ok {
		return false
	}
	for _, role := range TenantOwnerRoles {
		if m.Role == role {
			return true
		}
	}
	return false
}

// unrestrictedGrant is the ship-day answer, and the reason this feature can
// be deployed before anybody has decided anything.
//
// A member of an unrestricted tenant resolves to implicitRootLevel — the same
// authority they had the day before this package existed. A non-member
// resolves to nothing, which is also unchanged: tenant isolation was always
// enforced and this feature does not touch it.
func (r *ACLResolver) unrestrictedGrant(access *Access, tenantID string) EffectiveGrant {
	if ownerIsFloored(access, tenantID) {
		return EffectiveGrant{Level: LevelAdmin, Via: ViaTenantOwnerFloor}
	}
	if access.HasTenant(tenantID) {
		return EffectiveGrant{Level: implicitRootLevel, Via: ViaUnrestricted}
	}
	return EffectiveGrant{Level: LevelNone}
}

// implicitRootLevel is the level the ALL-TENANT-MEMBERS class holds at the
// tenant root when nobody has said otherwise — the parent-of-last-resort
// above every root package.
//
// IT IS ADMIN, AND THAT IS A RULING, NOT A DEFAULT SOMEBODY PICKED.
// Director decision 278ead22 on nw#3058, and it exists to make criterion zero
// TRUE rather than approximately true. The accepted 2026-08-08 baseline of
// this product is "any tenant member may do anything in their tenant until an
// owner restricts it", and the legacy per-package model (migration 0051)
// resolved a package with no grant anywhere on its path to FULL. So the new
// model must resolve an untouched node to exactly that, for members, on ship
// day — anything lower would be a silent fleet-wide narrowing dressed up as a
// schema migration, which is the precise regression criterion zero exists to
// prevent.
//
// It is CUT OFF by a break, like any inherited grant: a node with
// inherit=false takes nothing from above, including this. That is what makes
// "private planning in one action — only me and the people I name" (nw#2291)
// expressible as break-plus-explicit-grants.
//
// WHETHER THIS SHOULD LATER BE LOWERED — members to read_write, ACL edits to
// admins only — is a product ruling for Andrew with its own migration and its
// own proof. It is deliberately NOT smuggled in here, and changing this one
// constant is not the way to do it: the change needs a migration that writes
// real entries, so that what every member holds is visible on a permissions
// page rather than implied by a Go constant.
const implicitRootLevel = LevelAdmin

// ─── the entry algebra ───────────────────────────────────────────────────

// walk computes effective(node) for one already-expanded principal set.
//
//	effective(node) = direct(node) ∪ [ if inherit(node):
//	                    ∪ over every CONTAINS-parent p: effective(p) ]
//
// Memoized per (tenant, principal set, node) so a diamond is evaluated once,
// and cycle-guarded so a containment graph that has gone wrong produces a
// wrong-but-bounded answer rather than a hung request. A cycle in CONTAINS is
// a data fault; refusing to terminate is a worse response to it than
// answering from the acyclic part.
func (r *ACLResolver) walk(ctx context.Context, tenantID, nodeID string, p principalSet) (EffectiveGrant, error) {
	if err := r.loadNodes(ctx, tenantID, []string{nodeID}); err != nil {
		return EffectiveGrant{}, err
	}
	visiting := map[string]bool{}
	return r.walkFrom(ctx, tenantID, nodeID, p, visiting)
}

func (r *ACLResolver) walkFrom(ctx context.Context, tenantID, nodeID string,
	p principalSet, visiting map[string]bool) (EffectiveGrant, error) {

	if visiting[nodeID] {
		return EffectiveGrant{Level: LevelNone}, nil
	}
	// Memoized WITH its provenance, not just its level: "why can X see this"
	// must name the same chain on the second call as on the first, and a memo
	// that kept only the level would invent a plausible-looking wrong answer
	// for every repeat.
	memoKey := tenantID + "\x00" + p.digest + "\x00" + nodeID
	if g, ok := r.memo(memoKey); ok {
		return g, nil
	}
	visiting[nodeID] = true
	defer delete(visiting, nodeID)

	best := EffectiveGrant{Level: LevelNone}

	// direct(node): every live entry on this node whose principal the caller
	// expands to.
	for _, e := range r.entriesOf(tenantID, nodeID) {
		if !p.has(e.PrincipalKind, e.PrincipalID) {
			continue
		}
		if Max(best.Level, e.Role) != best.Level {
			best = EffectiveGrant{
				Level: e.Role, Via: ViaEntry,
				SourceNodeID: e.NodeID, SourceEntryID: e.ID,
			}
		}
	}

	node, known := r.nodeOf(tenantID, nodeID)
	// A node the store does not know about is treated as a root that
	// inherits: unknown structure must not silently BREAK inheritance, which
	// would narrow somebody because of a missing row.
	inherit := true
	var parents []string
	if known {
		inherit = node.Inherit
		parents = node.ParentIDs
	}

	if inherit {
		if len(parents) == 0 {
			// The tenant root. Every root package's parent-of-last-resort is
			// the tenant itself, carrying the implicit all_tenant_members
			// grant — see implicitRootLevel.
			if p.has(PrincipalClass, ClassAllTenantMembers) {
				if Max(best.Level, implicitRootLevel) != best.Level {
					best = EffectiveGrant{Level: implicitRootLevel, Via: ViaTenantMemberDefault}
				}
			}
		}
		for _, parentID := range parents {
			up, err := r.walkFrom(ctx, tenantID, parentID, p, visiting)
			if err != nil {
				return EffectiveGrant{}, err
			}
			if Max(best.Level, up.Level) != best.Level {
				best = up
			}
		}
	}

	r.putMemo(memoKey, best)
	return best, nil
}

// ─── principal expansion ─────────────────────────────────────────────────

// principalSet is one caller expanded into every principal an entry could
// name them by, plus a stable digest used as a memo key.
type principalSet struct {
	keys   map[string]bool
	digest string
}

func (p principalSet) has(kind PrincipalKind, id string) bool {
	return p.keys[principalKey(kind, id)]
}

// principalsFor expands a caller: themselves, their groups, and the virtual
// classes their membership admits them to.
//
// A NON-MEMBER (a guest from another tenant) expands to their person id
// ALONE. That is what makes the corrected formula of decision 67c69f0f
// [12/12] work — readable = [member path] OR [entry path] — without a second
// code path: entries both NARROW members, via a break, and EXTEND to named
// outsiders, because a guest's person entry matches while no class of theirs
// does.
func (r *ACLResolver) principalsFor(ctx context.Context, access *Access, tenantID, personID string) (principalSet, error) {
	groups, err := r.groupsOf(ctx, tenantID, personID)
	if err != nil {
		return principalSet{}, err
	}
	keys := map[string]bool{principalKey(PrincipalPerson, personID): true}
	for _, g := range groups {
		keys[principalKey(PrincipalGroup, g)] = true
	}
	if access.HasTenant(tenantID) {
		keys[principalKey(PrincipalClass, ClassAllTenantMembers)] = true
		if access.IsAgent {
			keys[principalKey(PrincipalClass, ClassAllAgentsOfMembers)] = true
		}
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	digest := ""
	for _, k := range ordered {
		digest += k + "|"
	}
	return principalSet{keys: keys, digest: digest}, nil
}

// ─── the list face ───────────────────────────────────────────────────────

// ReadableSet is what a list query may match: either EVERYTHING the tenant
// scope already allows, or an explicit set of package ids.
//
// The All case is not "all packages in the database" — it is "this feature
// adds no narrowing", so the caller's existing tenant predicate stands alone
// and the query is byte-identical to what it was before. That distinction is
// the whole of criterion zero, which is why All is a separate field rather
// than a sentinel value in IDs.
type ReadableSet struct {
	// All means impose no package narrowing at all.
	All bool
	// IDs is the readable package set when All is false. NEVER NIL when All
	// is false: an empty non-nil slice feeds `WHERE project_id = ANY($1)`,
	// which matches nothing — fail-closed by construction rather than by how
	// nil happens to marshal.
	IDs []string
}

// Contains reports whether nodeID is readable under this set.
func (s ReadableSet) Contains(nodeID string) bool {
	if s.All {
		return true
	}
	for _, id := range s.IDs {
		if id == nodeID {
			return true
		}
	}
	return false
}

// ReadableSetFor answers "which packages may this caller read in this
// tenant", generalizing the tenantIDs narrowing that list call sites already
// use.
//
// ONE PASS, NOT A WALK PER PACKAGE. On an unrestricted tenant it is a single
// cached existence check and returns All. On a restricted one it loads the
// tenant's whole (small) tree and its entries once, then evaluates in memory
// — never a graph query per package, and never anything per ROW of the list
// being filtered.
//
// The threshold is LevelRead, because that is what "readable" means. Callers
// needing a higher bar for a list (rare) should filter the returned set.
func (r *ACLResolver) ReadableSetFor(ctx context.Context, access *Access, tenantID string) (ReadableSet, error) {
	if access == nil || tenantID == "" {
		return ReadableSet{IDs: []string{}}, nil
	}
	restricted, err := r.restricted(ctx, tenantID)
	if err != nil {
		return ReadableSet{IDs: []string{}}, err
	}
	if !restricted {
		if r.unrestrictedGrant(access, tenantID).Level.AtLeast(LevelRead) {
			return ReadableSet{All: true}, nil
		}
		return ReadableSet{IDs: []string{}}, nil
	}

	if err := r.loadNodes(ctx, tenantID, nil); err != nil {
		return ReadableSet{IDs: []string{}}, err
	}
	r.mu.Lock()
	all := sortedKeys(r.nodes[tenantID])
	r.mu.Unlock()

	if err := r.loadEntries(ctx, tenantID, all); err != nil {
		return ReadableSet{IDs: []string{}}, err
	}

	out := ReadableSet{IDs: []string{}}
	for _, nodeID := range all {
		lvl, err := r.Effective(ctx, access, tenantID, nodeID)
		if err != nil {
			return ReadableSet{IDs: []string{}}, err
		}
		if lvl.AtLeast(LevelRead) {
			out.IDs = append(out.IDs, nodeID)
		}
	}
	return out, nil
}

// ─── the transpose ───────────────────────────────────────────────────────

// Reach is one grant that reaches a node: who, at what level, from where.
type Reach struct {
	PrincipalKind PrincipalKind
	PrincipalID   string
	Role          Level
	// SourceNodeID is the node the entry physically sits on — the node itself
	// for a direct grant, an ancestor for an inherited one. This is what makes
	// "who can reach Y" actionable: it names the row to change.
	SourceNodeID  string
	SourceEntryID string
	// Inherited reports that the grant came from above rather than from this
	// node.
	Inherited bool
}

// ReachingEntries is the transpose — "who can reach Y" — as far as the
// ALGEBRA can answer it: every entry that admits somebody to nodeID, direct
// or inherited, with groups and classes left UNEXPANDED.
//
// Expansion stops here on purpose, and the boundary is decision f3774718
// [9/12]. Turning a group into its members, or all_tenant_members into a
// roster, requires knowing WHO IS IN THE TENANT — an app fact this package
// deliberately cannot see, and one that differs per product. So the substrate
// answers the part that is the same everywhere (which entries reach this
// node, through which chain) and the app renders the part only it can know.
// The alternative — a fifth store method returning a roster — would put a
// membership directory behind an authorization interface for the sake of one
// screen.
//
// The IMPLICIT tenant-member grant is reported as an unexpanded
// all_tenant_members class entry with an empty SourceEntryID, so a
// permissions page shows the default that is actually in force rather than an
// empty list that reads as "nobody".
func (r *ACLResolver) ReachingEntries(ctx context.Context, tenantID, nodeID string) ([]Reach, error) {
	if tenantID == "" || nodeID == "" {
		return []Reach{}, nil
	}
	if err := r.loadNodes(ctx, tenantID, []string{nodeID}); err != nil {
		return nil, err
	}
	out := []Reach{}
	seen := map[string]bool{}
	visiting := map[string]bool{}

	var collect func(id string, inherited bool) error
	collect = func(id string, inherited bool) error {
		if visiting[id] {
			return nil
		}
		visiting[id] = true
		defer delete(visiting, id)

		for _, e := range r.entriesOf(tenantID, id) {
			key := principalKey(e.PrincipalKind, e.PrincipalID) + "\x00" + e.NodeID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Reach{
				PrincipalKind: e.PrincipalKind, PrincipalID: e.PrincipalID,
				Role: e.Role, SourceNodeID: e.NodeID, SourceEntryID: e.ID,
				Inherited: inherited,
			})
		}
		node, known := r.nodeOf(tenantID, id)
		if known && !node.Inherit {
			return nil
		}
		parents := node.ParentIDs
		if len(parents) == 0 {
			key := principalKey(PrincipalClass, ClassAllTenantMembers) + "\x00"
			if !seen[key] {
				seen[key] = true
				out = append(out, Reach{
					PrincipalKind: PrincipalClass, PrincipalID: ClassAllTenantMembers,
					Role: implicitRootLevel, Inherited: inherited,
				})
			}
			return nil
		}
		for _, parentID := range parents {
			if err := collect(parentID, true); err != nil {
				return err
			}
		}
		return nil
	}
	if err := collect(nodeID, false); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PrincipalKind != out[j].PrincipalKind {
			return out[i].PrincipalKind < out[j].PrincipalKind
		}
		if out[i].PrincipalID != out[j].PrincipalID {
			return out[i].PrincipalID < out[j].PrincipalID
		}
		return out[i].SourceNodeID < out[j].SourceNodeID
	})
	return out, nil
}

// ─── store access and the request cache ──────────────────────────────────

func (r *ACLResolver) restricted(ctx context.Context, tenantID string) (bool, error) {
	r.mu.Lock()
	if v, ok := r.presence[tenantID]; ok {
		r.mu.Unlock()
		return v, nil
	}
	r.mu.Unlock()

	v, err := r.store.TenantACLPresence(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("acl presence for %q: %w", tenantID, err)
	}
	r.mu.Lock()
	r.presence[tenantID] = v
	r.mu.Unlock()
	return v, nil
}

// loadNodes fetches the ancestor closure for nodeIDs, or the whole tenant
// tree when nodeIDs is nil, and merges it into the request cache. A tenant
// whose whole tree is already loaded never asks again.
func (r *ACLResolver) loadNodes(ctx context.Context, tenantID string, nodeIDs []string) error {
	r.mu.Lock()
	if r.full[tenantID] {
		r.mu.Unlock()
		return nil
	}
	known := r.nodes[tenantID]
	missing := []string{}
	for _, id := range nodeIDs {
		if _, ok := known[id]; !ok {
			missing = append(missing, id)
		}
	}
	r.mu.Unlock()

	if nodeIDs != nil && len(missing) == 0 {
		return nil
	}

	fetched, err := r.store.AncestorChains(ctx, tenantID, missing)
	if err != nil {
		return fmt.Errorf("ancestor chains for %q: %w", tenantID, err)
	}
	ids := make([]string, 0, len(fetched))

	r.mu.Lock()
	if r.nodes[tenantID] == nil {
		r.nodes[tenantID] = map[string]NodeACL{}
	}
	for id, n := range fetched {
		r.nodes[tenantID][id] = n
		ids = append(ids, id)
	}
	if nodeIDs == nil {
		r.full[tenantID] = true
	}
	r.mu.Unlock()

	return r.loadEntries(ctx, tenantID, ids)
}

func (r *ACLResolver) loadEntries(ctx context.Context, tenantID string, nodeIDs []string) error {
	r.mu.Lock()
	known := r.entries[tenantID]
	missing := []string{}
	for _, id := range nodeIDs {
		if _, ok := known[id]; !ok {
			missing = append(missing, id)
		}
	}
	r.mu.Unlock()

	if len(missing) == 0 {
		return nil
	}
	fetched, err := r.store.EntriesFor(ctx, tenantID, missing)
	if err != nil {
		return fmt.Errorf("acl entries for %q: %w", tenantID, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[tenantID] == nil {
		r.entries[tenantID] = map[string][]ACLEntry{}
	}
	for _, id := range missing {
		// Record the EMPTY answer too. Otherwise a node with no entries is
		// re-fetched on every reference, which is the per-rung query this
		// design exists to avoid.
		r.entries[tenantID][id] = fetched[id]
	}
	return nil
}

func (r *ACLResolver) groupsOf(ctx context.Context, tenantID, personID string) ([]string, error) {
	r.mu.Lock()
	if g, ok := r.groups[tenantID][personID]; ok {
		r.mu.Unlock()
		return g, nil
	}
	r.mu.Unlock()

	fetched, err := r.store.GroupMemberships(ctx, tenantID, []string{personID})
	if err != nil {
		return nil, fmt.Errorf("group memberships for %q: %w", tenantID, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups[tenantID] == nil {
		r.groups[tenantID] = map[string][]string{}
	}
	for id, g := range fetched {
		r.groups[tenantID][id] = g
	}
	if _, ok := r.groups[tenantID][personID]; !ok {
		r.groups[tenantID][personID] = []string{}
	}
	return r.groups[tenantID][personID], nil
}

func (r *ACLResolver) entriesOf(tenantID, nodeID string) []ACLEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[tenantID][nodeID]
}

func (r *ACLResolver) nodeOf(tenantID, nodeID string) (NodeACL, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[tenantID][nodeID]
	return n, ok
}

func (r *ACLResolver) memo(key string) (EffectiveGrant, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.levels[key]
	return v, ok
}

func (r *ACLResolver) putMemo(key string, g EffectiveGrant) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.levels[key] = g
}
