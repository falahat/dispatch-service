package artifact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/falahat/dispatch-service/internal/artifact"
)

func TestComputeAndValidateAddress(t *testing.T) {
	a := artifact.ComputeAddress([]byte("hello"))
	// sha256("hello") is well-known.
	const want = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if string(a) != want {
		t.Fatalf("address = %s, want %s", a, want)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("valid address rejected: %v", err)
	}
	if !a.Matches([]byte("hello")) {
		t.Fatal("Matches should be true for original bytes")
	}
	if a.Matches([]byte("hell0")) {
		t.Fatal("Matches must be false for different bytes")
	}
}

func TestMalformedAddresses(t *testing.T) {
	bad := []string{
		"",
		"sha256:",
		"sha1:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		"sha256:2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824", // uppercase
		"sha256:xyz",
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",         // no scheme
		"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982",   // 63 hex
		"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b98244", // 65 hex
	}
	for _, b := range bad {
		if err := artifact.Address(b).Validate(); err == nil {
			t.Errorf("expected %q to be rejected", b)
		}
	}
}

// TestTraversalGuard is the security check: no path escapes the workdir.
func TestTraversalGuard(t *testing.T) {
	attacks := []string{
		"../etc/passwd",
		"a/../../etc/passwd",
		"..",
		"a/..",
		"../",
		"/etc/passwd",            // absolute
		`a\b`,                    // backslash (windows separator)
		`..\..\windows`,          // backslash traversal
		"a/b/../../../c",         // deep traversal
		"foo/\x00bar",            // NUL
		"foo/\x01bar",            // control char
		strings.Repeat("a", 513), // over length
		"",                       // empty
	}
	for _, p := range attacks {
		if err := artifact.ValidateRelPath(p); err == nil {
			t.Errorf("traversal guard failed to reject %q", p)
		}
	}
	ok := []string{"a", "a/b", "ep-0042/embeddings.bin", "a.b.c", "..foo", "foo..bar", "a/..b/c"}
	for _, p := range ok {
		if err := artifact.ValidateRelPath(p); err != nil {
			t.Errorf("valid path %q rejected: %v", p, err)
		}
	}
}

// TestCanonicalParamsIntegerOnly enforces the cross-language determinism rule.
func TestCanonicalParamsIntegerOnly(t *testing.T) {
	good := []string{
		`{}`,
		`{"a": 1}`,
		`{"a": -42, "b": "0.7"}`,
		`{"nested": {"x": [1, 2, 3], "s": "text"}}`,
		`{"flag": true, "nothing": null}`,
		`{"big": 9007199254740993}`, // integer beyond float53 stays integer as a string of digits
	}
	for _, s := range good {
		if err := artifact.ValidateCanonicalParams(json.RawMessage(s)); err != nil {
			t.Errorf("valid params %s rejected: %v", s, err)
		}
	}
	bad := []string{
		`{"temp": 0.7}`,      // fractional
		`{"x": 1e3}`,         // exponent
		`{"x": 1.0}`,         // trailing .0 is still a float form
		`{"a": [1, 2.5]}`,    // nested float
		`{"n": {"m": 3.14}}`, // deep float
		`[1,2,3]`,            // params must be an object
		`"string"`,           // not an object
		`42`,                 // not an object
		`{"a": 1} trailing`,  // trailing data
	}
	for _, s := range bad {
		if err := artifact.ValidateCanonicalParams(json.RawMessage(s)); err == nil {
			t.Errorf("invalid params %s accepted", s)
		}
	}
}

func TestInvocationValidate(t *testing.T) {
	const a = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	inv := artifact.Invocation{
		Kind:      artifact.InvocationKind,
		Op:        "transcribe",
		OpVersion: 2,
		Params:    json.RawMessage(`{"language":"en","temperature":"0.0"}`),
		Inputs:    map[string]artifact.Input{"audio": {Address: a, Kind: artifact.KindBlob}},
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("valid invocation rejected: %v", err)
	}

	bad := inv
	bad.Op = "Transcribe" // uppercase not allowed
	if err := bad.Validate(); err == nil {
		t.Error("uppercase op accepted")
	}

	bad = inv
	bad.OpVersion = 0
	if err := bad.Validate(); err == nil {
		t.Error("op_version 0 accepted")
	}

	bad = inv
	bad.Inputs = map[string]artifact.Input{"audio": {Address: "not-an-address", Kind: artifact.KindBlob}}
	if err := bad.Validate(); err == nil {
		t.Error("malformed input address accepted")
	}
}

func TestManifestValidateRejectsTraversal(t *testing.T) {
	const a = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	m := artifact.Manifest{
		Kind: artifact.ManifestKind,
		Entries: []artifact.ManifestEntry{
			{Path: "../escape", Address: a, Size: 1},
		},
	}
	if err := m.Validate(); err == nil {
		t.Fatal("manifest with traversal path accepted")
	}
}

func TestActionResultValidate(t *testing.T) {
	const a = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	r := artifact.ActionResult{
		Kind:              artifact.ActionResultKind,
		InvocationAddress: a,
		Outputs:           map[string]artifact.Output{"out": {Address: a, Size: 10}},
		Metrics:           map[string]int64{"wall_s": 5},
		Runner:            artifact.RunnerInfo{Node: "n", Version: "v"},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid action_result rejected: %v", err)
	}
	bad := r
	bad.Runner.Node = ""
	if err := bad.Validate(); err == nil {
		t.Error("action_result with empty runner node accepted")
	}
}
