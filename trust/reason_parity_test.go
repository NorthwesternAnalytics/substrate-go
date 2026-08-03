package trust

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// REASON-CODE PARITY, ASSERTED AGAINST THE DART SOURCE.
//
// The client's FeatureDecisionEngine and this module both refuse things, and
// they must name the same causes. Keeping two lists in step by hand works
// until the day somebody adds a code to one of them — so this test reads the
// other side's source and compares, rather than trusting a comment that says
// they match.
//
// It is a cross-repository read, which is unusual and deliberate. The two
// repositories are checked out side by side in the substrate workspace, so the
// default path finds the file; where it does not (a CI job with only this
// repository), the test SKIPS rather than failing, and
// SUBSTRATE_FEATURE_DECISION_DART points it at the file explicitly. A skipped
// parity test is honest about having checked nothing; a deleted one is not.
//
// When this module graduates to its own repository, this is the one test that
// needs a decision: either keep the env var and run it in the workspace, or
// publish the code list from substrate_contract as a small generated artifact
// both sides consume.

const dartRelativePath = "../../../../../platform/nwa.bundle.platform.shell/" +
	"packages/substrate_contract/lib/src/feature/feature_decision.dart"

func dartSource(t *testing.T) string {
	t.Helper()
	path := os.Getenv("SUBSTRATE_FEATURE_DECISION_DART")
	if path == "" {
		path = dartRelativePath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		abs, _ := filepath.Abs(path)
		t.Skipf("substrate_contract's feature_decision.dart not readable at %s (%v) — "+
			"set SUBSTRATE_FEATURE_DECISION_DART to assert reason-code parity", abs, err)
	}
	return string(data)
}

var dartConstPattern = regexp.MustCompile(`static const String \w+ = '([^']+)';`)

// Every code the Dart engine can produce must exist here. A refusal the client
// understands and the backend cannot express is a refusal that arrives at a
// screen as an unexplained 403.
func TestEveryDartReasonCodeExistsInGo(t *testing.T) {
	source := dartSource(t)

	dart := map[string]bool{}
	for _, m := range dartConstPattern.FindAllStringSubmatch(source, -1) {
		dart[m[1]] = true
	}
	if len(dart) == 0 {
		t.Fatal("no reason codes parsed from feature_decision.dart — the parity check is " +
			"passing without checking anything")
	}

	known := map[string]bool{}
	for _, code := range ReasonCodes {
		known[code] = true
	}

	var missing []string
	for code := range dart {
		if !known[code] {
			missing = append(missing, code)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("reason codes the client engine produces and this module cannot name: %v\n"+
			"add them to reason.go — never rename an existing one", missing)
	}
}

// And the reverse: a code this module invents that no client understands
// renders as a bare error string on a screen, which is how "why can't I do
// this?" becomes unanswerable.
func TestEveryGoReasonCodeExistsInDart(t *testing.T) {
	source := dartSource(t)

	for _, code := range ReasonCodes {
		if !strings.Contains(source, "'"+code+"'") {
			t.Errorf("reason code %q has no counterpart in substrate_contract's "+
				"FeatureReasonCode; either add it there or stop emitting it here", code)
		}
	}
}

// The status vocabulary too: Dart's FeatureDecisionStatus enum names the
// outcome CLASSES, and a status this module emits that the client cannot
// switch on is the same failure one level up.
func TestDecisionStatusesMatchTheDartEnum(t *testing.T) {
	source := dartSource(t)

	enum := regexp.MustCompile(`(?s)enum FeatureDecisionStatus \{(.*?)\n\}`).FindStringSubmatch(source)
	if enum == nil {
		t.Skip("FeatureDecisionStatus enum not found — the Dart file's shape changed")
	}
	for _, status := range DecisionStatuses {
		// Enum values appear as bare identifiers in the body.
		if !regexp.MustCompile(`\b` + string(status) + `\b`).MatchString(enum[1]) {
			t.Errorf("status %q is not a FeatureDecisionStatus value", status)
		}
	}
}

// The codes this module actually EMITS today, pinned by name. The two tests
// above prove the vocabularies agree; this one proves the four codes the
// backend can currently produce are the ones we think they are, so a rename
// here fails loudly rather than silently changing an API contract.
func TestTheCodesThisModuleEmitsAreStable(t *testing.T) {
	emitted := map[string]string{
		"allowed":               ReasonAllowed,
		"missing entitlement":   ReasonTenantNotEntitled,
		"insufficient role":     ReasonRoleDenied,
		"ambiguous tenant":      ReasonFocusRequired,
		"not a member/licensed": ReasonTenantNotLicensed,
	}
	want := map[string]string{
		"allowed":               "allowed",
		"missing entitlement":   "tenant_not_entitled",
		"insufficient role":     "role_denied",
		"ambiguous tenant":      "focus_required",
		"not a member/licensed": "tenant_not_licensed",
	}
	for name, got := range emitted {
		if got != want[name] {
			t.Errorf("%s emits %q, want %q — released reason codes are a contract",
				name, got, want[name])
		}
	}
}
