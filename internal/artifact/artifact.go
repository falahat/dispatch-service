// Package artifact defines the CAS-borne artifacts of the dispatch plane:
// addresses, invocations, manifests, and action results. These types are the
// Go realization of contracts/schemas/artifacts.schema.json. Every component
// that reads or writes the CAS shares them.
//
// Design invariants enforced here (see contracts/README.md):
//   - content addressing is identity: an Address is sha256(bytes), validated
//     as data and never interpolated into a path unchecked;
//   - integer-only params: among JSON numbers only integers are legal in an
//     invocation's params, so compute containers in any language parse them
//     unambiguously (decimals ride as strings);
//   - traversal guard: manifest paths are relative, ..-free, backslash-free,
//     control-char-free — checked here in addition to the schema;
//   - a local artifact is a place, not content: it names a file or folder on one
//     node under one of the roots that node's runner was installed with, and
//     nothing hashes or copies it.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Address is a content address: "sha256:" followed by 64 lowercase hex digits.
type Address string

var addressRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ComputeAddress returns the canonical Address for a byte slice.
func ComputeAddress(b []byte) Address {
	sum := sha256.Sum256(b)
	return Address("sha256:" + hex.EncodeToString(sum[:]))
}

// Validate reports whether the address is well-formed. An address is data:
// callers MUST validate its shape before any filesystem or URL use.
func (a Address) Validate() error {
	if !addressRe.MatchString(string(a)) {
		return fmt.Errorf("artifact: malformed address %q", string(a))
	}
	return nil
}

// Hex returns the 64-char hex digest without the "sha256:" scheme. The address
// MUST already be validated.
func (a Address) Hex() string { return strings.TrimPrefix(string(a), "sha256:") }

// Matches reports whether b hashes to this address. This is the verify-on-read
// / verify-on-write check every consumer MUST perform.
func (a Address) Matches(b []byte) bool { return ComputeAddress(b) == a }

// Kind enumerates how an input reaches the compute and where an output is kept.
type Kind string

const (
	KindBlob     Kind = "blob"
	KindManifest Kind = "manifest"
	KindLocal    Kind = "local"
)

// Input is one named input of an invocation: a blob or a manifest by address,
// or a local artifact by its place.
type Input struct {
	Address Address `json:"address,omitempty"`
	Kind    Kind    `json:"kind"`
	Place
}

// Output is one named output of an action result: the address and size of one
// blob. Kind manifest means that blob is a manifest of a folder's files. An
// empty Kind is a blob, so results stored before folder outputs stay valid.
// Kind local is an output kept where the compute wrote it: its place, and the
// file's size (a folder's is not counted).
type Output struct {
	Address Address `json:"address,omitempty"`
	Size    int64   `json:"size"`
	Kind    Kind    `json:"kind,omitempty"`
	Place
}

// Place locates a local artifact: Path under the root named Root that Node's
// runner was installed with. The node's runner is the only component that
// resolves it, and only inside that root.
type Place struct {
	Node string `json:"node,omitempty"`
	Root string `json:"root,omitempty"`
	Path string `json:"path,omitempty"`
}

var nodeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate checks that the place names a node and a root in their own shapes,
// and a path in the one spelling ValidatePlacePath allows.
func (p Place) Validate() error {
	if !nodeRe.MatchString(p.Node) {
		return fmt.Errorf("artifact: invalid node %q", p.Node)
	}
	if !nameRe.MatchString(p.Root) {
		return fmt.Errorf("artifact: invalid root %q", p.Root)
	}
	return ValidatePlacePath(p.Path)
}

// validateKind checks the fields one input or output of this kind carries: an
// address for blob and manifest, a place for local, never both.
func validateKind(kind Kind, address Address, place Place) error {
	switch kind {
	case KindBlob, KindManifest:
		if place != (Place{}) {
			return fmt.Errorf("a %s names no place", kind)
		}
		return address.Validate()
	case KindLocal:
		if address != "" {
			return errors.New("a local artifact has no address")
		}
		return place.Validate()
	default:
		return fmt.Errorf("invalid kind %q", kind)
	}
}

// Invocation is the app-authored description of one computation. It is stored
// in the CAS verbatim; its own address is its computation identity. Params is
// kept as raw bytes: no non-app component canonicalizes or reinterprets it,
// and keeping it raw preserves the exact bytes handed to the compute container.
type Invocation struct {
	Kind      string           `json:"kind"` // must be "invocation/v0"
	Op        string           `json:"op"`
	OpVersion int              `json:"op_version"`
	Params    json.RawMessage  `json:"params"`
	Inputs    map[string]Input `json:"inputs"`
}

const (
	InvocationKind   = "invocation/v0"
	ManifestKind     = "manifest/v0"
	ActionResultKind = "action_result/v0"
)

var (
	opRe   = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	nameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// Validate checks the invocation's structure and every address within it.
func (inv *Invocation) Validate() error {
	if inv.Kind != InvocationKind {
		return fmt.Errorf("artifact: invocation kind %q, want %q", inv.Kind, InvocationKind)
	}
	if !opRe.MatchString(inv.Op) {
		return fmt.Errorf("artifact: invalid op %q", inv.Op)
	}
	if inv.OpVersion < 1 {
		return fmt.Errorf("artifact: op_version must be >= 1, got %d", inv.OpVersion)
	}
	if len(inv.Inputs) > 64 {
		return fmt.Errorf("artifact: too many inputs: %d", len(inv.Inputs))
	}
	if len(inv.Params) > 0 {
		if err := ValidateCanonicalParams(inv.Params); err != nil {
			return err
		}
	}
	for name, in := range inv.Inputs {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("artifact: invalid input name %q", name)
		}
		if err := validateKind(in.Kind, in.Address, in.Place); err != nil {
			return fmt.Errorf("artifact: input %q: %w", name, err)
		}
	}
	return nil
}

// ManifestEntry is one file within a manifest: a traversal-safe relative path,
// its address, and its size.
type ManifestEntry struct {
	Path    string  `json:"path"`
	Address Address `json:"address"`
	Size    int64   `json:"size"`
}

// Manifest is a set of addressed files under relative paths, itself a CAS blob.
type Manifest struct {
	Kind    string          `json:"kind"` // must be "manifest/v0"
	Entries []ManifestEntry `json:"entries"`
}

// MaxManifestEntries bounds the files one manifest may name.
const MaxManifestEntries = 65536

// Validate checks the manifest, re-checking every path against the traversal
// guard (schema-level guard is not trusted alone) and every address.
func (m *Manifest) Validate() error {
	if m.Kind != ManifestKind {
		return fmt.Errorf("artifact: manifest kind %q, want %q", m.Kind, ManifestKind)
	}
	if len(m.Entries) > MaxManifestEntries {
		return fmt.Errorf("artifact: too many manifest entries: %d", len(m.Entries))
	}
	for i := range m.Entries {
		e := &m.Entries[i]
		if err := ValidateRelPath(e.Path); err != nil {
			return fmt.Errorf("artifact: manifest entry %d: %w", i, err)
		}
		if err := e.Address.Validate(); err != nil {
			return fmt.Errorf("artifact: manifest entry %d: %w", i, err)
		}
		if e.Size < 0 {
			return fmt.Errorf("artifact: manifest entry %d: negative size", i)
		}
	}
	return nil
}

// RunnerInfo identifies which runner produced an action result.
type RunnerInfo struct {
	Node    string `json:"node"`
	Version string `json:"version"`
}

// ActionResult is the runner's complete payload: addresses and integer metrics
// only, never domain bytes. invocation_address is echoed from the grant.
type ActionResult struct {
	Kind              string            `json:"kind"` // must be "action_result/v0"
	InvocationAddress Address           `json:"invocation_address"`
	Outputs           map[string]Output `json:"outputs"`
	Metrics           map[string]int64  `json:"metrics"`
	Runner            RunnerInfo        `json:"runner"`
}

var metricNameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Validate checks the action result's structure and every address.
func (r *ActionResult) Validate() error {
	if r.Kind != ActionResultKind {
		return fmt.Errorf("artifact: action_result kind %q, want %q", r.Kind, ActionResultKind)
	}
	if err := r.InvocationAddress.Validate(); err != nil {
		return fmt.Errorf("artifact: action_result invocation_address: %w", err)
	}
	if len(r.Outputs) > 64 {
		return fmt.Errorf("artifact: too many outputs: %d", len(r.Outputs))
	}
	for name, out := range r.Outputs {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("artifact: invalid output name %q", name)
		}
		kind := out.Kind
		if kind == "" {
			kind = KindBlob
		}
		if err := validateKind(kind, out.Address, out.Place); err != nil {
			return fmt.Errorf("artifact: output %q: %w", name, err)
		}
		if out.Size < 0 {
			return fmt.Errorf("artifact: output %q: negative size", name)
		}
	}
	if len(r.Metrics) > 64 {
		return fmt.Errorf("artifact: too many metrics: %d", len(r.Metrics))
	}
	for name := range r.Metrics {
		if !metricNameRe.MatchString(name) {
			return fmt.Errorf("artifact: invalid metric name %q", name)
		}
	}
	if r.Runner.Node == "" || r.Runner.Version == "" {
		return errors.New("artifact: action_result runner node/version required")
	}
	return nil
}

// ValidateRelPath enforces the traversal guard: relative, no leading slash, no
// ".." segment, no backslash, no control characters (including NUL). This is
// the guard consumers MUST re-apply even though the schema also enforces it.
func ValidateRelPath(p string) error {
	if p == "" {
		return errors.New("artifact: empty path")
	}
	if len(p) > 512 {
		return fmt.Errorf("artifact: path too long: %d bytes", len(p))
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("artifact: absolute path not allowed: %q", p)
	}
	if strings.Contains(p, `\`) {
		return fmt.Errorf("artifact: backslash not allowed: %q", p)
	}
	for _, r := range p {
		if r < 0x20 {
			return fmt.Errorf("artifact: control char in path: %q", p)
		}
	}
	// Reject any ".." path segment.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("artifact: traversal segment in path: %q", p)
		}
	}
	return nil
}

// ValidatePlacePath is the traversal guard for a local artifact's path. It also
// refuses empty and "." segments, so one place has one spelling and equal
// places compare equal as strings.
func ValidatePlacePath(p string) error {
	if err := ValidateRelPath(p); err != nil {
		return err
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." {
			return fmt.Errorf("artifact: empty or . segment in path: %q", p)
		}
	}
	return nil
}

// ValidateCanonicalParams enforces the integer-only rule over a params object:
// among JSON numbers, only integers are legal (no fraction, no exponent);
// decimals must be strings. Recurses through arrays and objects.
func ValidateCanonicalParams(raw json.RawMessage) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("artifact: params not valid JSON: %w", err)
	}
	if dec.More() {
		return errors.New("artifact: params has trailing data")
	}
	if _, ok := v.(map[string]any); !ok {
		return errors.New("artifact: params must be an object")
	}
	return validateCanonical(v)
}

func validateCanonical(v any) error {
	switch t := v.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("artifact: non-integer number %q (decimals must be strings)", s)
		}
		return nil
	case []any:
		for _, e := range t {
			if err := validateCanonical(e); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, e := range t {
			if err := validateCanonical(e); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("artifact: unexpected value type %T", v)
	}
}
