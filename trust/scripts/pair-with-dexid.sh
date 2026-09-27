#!/usr/bin/env bash
#
# pair-with-dexid.sh — does DexID's real minter produce something this verifier
# really accepts? (nw#4409 acceptance 4)
#
# WHY A SCRIPT AND NOT A TEST. The minter lives in DexID's internal/ tree in
# another repository, and the verifier lives here. Go's internal-package rule
# makes a single test impossible, and importing across the two would couple a
# shared security library to one service. So each side is exercised by its own
# real code, in its own module, and this script is what puts them end to end —
# the same posture dexsite takes towards dexsweep (nw#4410).
#
# WHAT IT PROVES that neither side's unit tests can: that the bytes one writes are
# the bytes the other reads. Both sides' tests use a stub of the other, and two
# stubs can agree with each other while disagreeing with reality.
#
#   pair-with-dexid.sh --dexid-src /path/to/services/dexid
#
# Exit 0 means a genuinely minted assertion verified, AND a tampered one did not.
# Nothing is deployed, no host is touched, and the key is created in a temp dir
# that is removed on exit.

set -o errexit
set -o nounset
set -o pipefail

readonly PROGRAM="${0##*/}"

usage() {
	cat <<'USAGE'
usage: pair-with-dexid.sh --dexid-src DIR [--trust-src DIR]

  --dexid-src DIR   DexID's Go module (the directory holding its go.mod)
  --trust-src DIR   this module (default: two directories above this script)

exit 0  a real assertion verified and a tampered one was refused
exit 1  the two sides disagree
exit 2  the arguments are wrong, or Go is not available
USAGE
}

die() {
	printf '%s: %s\n' "$PROGRAM" "$1" >&2
	exit 2
}

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
dexid_src=""
trust_src="$(cd -- "$script_dir/../.." && pwd)"

while [ "$#" -gt 0 ]; do
	case "$1" in
	--dexid-src)
		[ "$#" -ge 2 ] || die "--dexid-src needs a directory"
		dexid_src="$2"
		shift 2
		;;
	--trust-src)
		[ "$#" -ge 2 ] || die "--trust-src needs a directory"
		trust_src="$2"
		shift 2
		;;
	-h | --help | help)
		usage
		exit 0
		;;
	*) die "unrecognised argument '$1' (try --help)" ;;
	esac
done

[ -n "$dexid_src" ] || die "--dexid-src is required"
[ -f "$dexid_src/go.mod" ] || die "$dexid_src has no go.mod; point --dexid-src at DexID's module root"
[ -f "$trust_src/go.mod" ] || die "$trust_src has no go.mod"
command -v go >/dev/null 2>&1 || die "go is not installed"

# /tmp is noexec on some hosts and `go test`/`go run` exec what they build, so
# both GOTMPDIR and the scratch tree live beside the source.
work="$(mktemp -d "$trust_src/.pair-with-dexid.XXXXXX")"
export GOTMPDIR="$work/gotmp"
mkdir -p "$GOTMPDIR"
trap 'rm -rf "$work"' EXIT

# ── The DexID side: its real key, its real minter, its real JWKS ─────────────
mkdir -p "$dexid_src/internal/assertion/pairprobe"
probe_dir="$dexid_src/internal/assertion/pairprobe"
trap 'rm -rf "$work" "$probe_dir"' EXIT
cat > "$probe_dir/main.go" <<'GO'
// Temporary, written and removed by pair-with-dexid.sh. It lives inside DexID's
// tree only because Go's internal-package rule puts internal/assertion out of
// reach from anywhere else.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dextech/dexid/internal/assertion"
)

func main() {
	key, err := assertion.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	minter, err := assertion.NewMinter(key, os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	token, err := minter.Mint(
		assertion.Identity{
			PersonID: "11111111-1111-1111-1111-111111111111",
			Issuer:   "https://issuer.example",
			Subject:  "22222222-2222-2222-2222-222222222222",
			AAL:      "aal2",
		},
		assertion.Request{Audience: os.Args[2], VerifyClass: "api", Host: "api.site.example"},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := json.Marshal(map[string]any{
		"token": token,
		"jwks":  assertion.Set(key),
		"kid":   key.ID,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
GO

readonly ISSUER="https://id.example"
readonly AUDIENCE="https://api.site.example"

echo "minting with DexID's own package ($dexid_src)"
minted="$(cd "$dexid_src" && GOTMPDIR="$GOTMPDIR" go run ./internal/assertion/pairprobe "$ISSUER" "$AUDIENCE")"
[ -n "$minted" ] || die "DexID's minter produced nothing"

# ── The verifier side: this module's real AssertionVerifier ──────────────────
mkdir -p "$trust_src/trust/pairprobe"
verify_dir="$trust_src/trust/pairprobe"
trap 'rm -rf "$work" "$probe_dir" "$verify_dir"' EXIT
cat > "$verify_dir/main.go" <<'GO'
// Temporary, written and removed by pair-with-dexid.sh.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/dextech/substrate-go/trust"
)

func main() {
	var minted struct {
		Token string          `json:"token"`
		JWKS  json.RawMessage `json:"jwks"`
		Kid   string          `json:"kid"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&minted); err != nil {
		fmt.Fprintln(os.Stderr, "reading the minted assertion:", err)
		os.Exit(1)
	}

	// DexID's published key set, served exactly as DexID serves it.
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(minted.JWKS)
	}))
	defer jwks.Close()

	verifier, err := trust.NewAssertionVerifier(trust.AssertionConfig{
		JWKSURL: jwks.URL, Issuer: os.Args[1], Audience: os.Args[2],
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	request := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, os.Args[2]+"/v1/widgets", nil)
		r.Header.Set(trust.HeaderPersonID, "11111111-1111-1111-1111-111111111111")
		r.Header.Set(trust.HeaderIssuer, "https://issuer.example")
		r.Header.Set(trust.HeaderSubject, "22222222-2222-2222-2222-222222222222")
		r.Header.Set(trust.HeaderAAL, "aal2")
		r.Header.Set(trust.HeaderAssertion, token)
		return r
	}

	// THE TAMPERED TOKEN GOES FIRST, and the order is the whole point. Checked
	// AFTER the genuine one, it carries the same jti and is refused by the REPLAY
	// cache rather than by the signature — so this script reported three passes
	// with signature verification switched off entirely, until the order changed.
	parts := strings.Split(minted.Token, ".")
	if len(parts) != 3 {
		fmt.Println("FAIL  the minted token is not a compact JWT")
		os.Exit(1)
	}
	swapped := "A"
	if strings.HasPrefix(parts[2], "A") {
		swapped = "B"
	}
	tampered := append([]string{}, parts...)
	tampered[2] = swapped + parts[2][1:]
	if _, err := verifier.Verify(context.Background(), request(strings.Join(tampered, "."))); err == nil {
		fmt.Println("FAIL  a tampered signature was accepted")
		os.Exit(1)
	}
	fmt.Println("PASS  a tampered signature was refused (before any genuine one was seen)")

	id, err := verifier.Verify(context.Background(), request(minted.Token))
	if err != nil {
		fmt.Printf("FAIL  DexID's own assertion was refused by the verifier: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS  a real assertion verified: person=%s aal=%s class=%s kid=%s\n",
		id.PersonID, id.AAL, id.VerifyClass, id.KeyID)
	if id.KeyID != minted.Kid {
		fmt.Printf("FAIL  kid mismatch: verifier saw %q, DexID minted with %q\n", id.KeyID, minted.Kid)
		os.Exit(1)
	}

	// And now the replay, which is a different control from the one above.
	if _, err := verifier.Verify(context.Background(), request(minted.Token)); err == nil {
		fmt.Println("FAIL  the same assertion was accepted twice")
		os.Exit(1)
	}
	fmt.Println("PASS  a replay was refused")
}
GO

echo "verifying with the trust kit's own package ($trust_src)"
printf '%s' "$minted" | (cd "$trust_src" && GOTMPDIR="$GOTMPDIR" go run ./trust/pairprobe "$ISSUER" "$AUDIENCE")
