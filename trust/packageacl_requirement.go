package trust

import (
	"context"
	"fmt"
)

// packageacl_requirement.go exposes the branch ACL through the SAME seam
// every other authorization question in this module already uses: a
// Requirement, judged by Decide/DecideFor, producing a Decision a handler can
// return and a client can render.
//
// That reuse is the point. A handler must not learn a second way to ask "may
// they do this" — decision cf03d84d [5/12] names per-verb ad-hoc checks in
// handlers as the drift failure nw#3050 forbids, and a bespoke bool-returning
// helper beside the Requirement machinery would be exactly that with better
// manners.

// packageAccessRequirement carries a threshold and the ALREADY-RESOLVED level
// the caller holds on the node in question.
//
// Why the level is resolved before the Requirement is built, rather than
// inside satisfiedBy: the Requirement interface answers from (Access,
// tenantID) alone — no context, no store, no node id — because it is
// evaluated per tenant in scope and must stay pure. Resolving a package level
// needs all three. Splitting it this way keeps the pure part pure and puts
// the I/O where I/O belongs, and it leaves the threshold logic trivially
// testable without a store at all.
type packageAccessRequirement struct {
	min  Level
	have Level
	// nodeID is carried for the refusal's label only, never for a decision.
	nodeID string
}

func (p packageAccessRequirement) label() string {
	if p.nodeID == "" {
		return "package " + string(p.min)
	}
	return fmt.Sprintf("package %s on %s", p.min, p.nodeID)
}

func (p packageAccessRequirement) satisfiedBy(_ *Access, _ string) bool {
	return p.have.AtLeast(p.min)
}

// deniedReason reuses ReasonRoleDenied rather than introducing an ACL-specific
// code, and that is a RULED choice with a shelf life (Director decision
// 278ead22 on nw#3058).
//
// The constraint: reason.go's ReasonCodes slice is parity-checked against the
// Dart client engine in substrate_contract (reason_parity_test.go), so a new
// code here fails that test until a matching change lands in the shell
// repository — a different repo, outside this packet. And nothing in INC-1
// enforces, so no client renders this refusal yet. Reusing the existing code
// is therefore honest today and costs nothing.
//
// INC-2 (nw#3059), which is where enforcement actually lands, decides the
// vocabulary WITH the client lane and ships the Dart counterpart in the same
// wave. Do not add a code here without that companion change; the parity test
// exists precisely so that "we'll do the client side later" cannot happen
// quietly.
func (p packageAccessRequirement) deniedReason() string { return ReasonRoleDenied }

func (p packageAccessRequirement) deniedExplanation() string {
	return fmt.Sprintf("this action requires %s access to this package", p.min)
}

func (p packageAccessRequirement) deniedRemediation() string {
	return "ask an administrator of this package to grant you access"
}

// RequirePackageAccess demands that the caller hold at least min on the node
// whose effective level is `have`.
//
// Pure: no store, no context, no I/O. Resolve the level with
// ACLResolver.Effective (or use the resolver's RequirePackageAccess, which
// does both), then hand the answer here.
func RequirePackageAccess(min, have Level) Requirement {
	return packageAccessRequirement{min: min, have: have}
}

// RequirePackageAccess resolves the caller's effective level on nodeID and
// returns the Requirement for min — the one-call form handlers should use.
//
// The Decision is then produced the ordinary way:
//
//	req, err := resolver.RequirePackageAccess(ctx, access, tenantID, pkgID, trust.LevelReadWrite)
//	if err != nil { ... }
//	if d := trust.DecideFor(access, tenantID, req); !d.Allowed() {
//		writeRefusal(w, d)
//		return
//	}
//
// NOT WIRED INTO ANY LIST OR GET HANDLER IN THIS INCREMENT. INC-1 ships the
// mechanism and proves it changed nothing; INC-2 (nw#3059) wires it. A call
// site added here would make ship-day behaviour non-identical, which is the
// one thing this increment promises not to do.
func (r *ACLResolver) RequirePackageAccess(ctx context.Context, access *Access,
	tenantID, nodeID string, min Level) (Requirement, error) {

	have, err := r.Effective(ctx, access, tenantID, nodeID)
	if err != nil {
		return nil, err
	}
	return packageAccessRequirement{min: min, have: have, nodeID: nodeID}, nil
}
