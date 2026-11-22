package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// Local artifacts (decisions D10, D11). A runner is installed with roots
// (--root NAME=DIR), as it is installed with its command. A local input names a
// path under one of them on this runner's node; the runner checks it through an
// os.Root opened on that root, so no "..", absolute path or link can lead
// outside, and hands the compute that path where it lies: nothing is copied,
// hashed or sent. A local output is a place the compute names under a root; the
// runner checks it the same way and reports it without reading or uploading it.

var rootNameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// ParseRoot reads one --root NAME=DIR: a root name in the artifacts contract's
// name shape and an absolute path to an existing folder.
func ParseRoot(s string) (name, dir string, err error) {
	name, dir, ok := strings.Cut(s, "=")
	if !ok || !rootNameRe.MatchString(name) {
		return "", "", fmt.Errorf("root %q: want NAME=DIR, NAME matching [a-z0-9_]{1,64}", s)
	}
	if !filepath.IsAbs(dir) {
		return "", "", fmt.Errorf("root %s: %q is not an absolute path", name, dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", "", fmt.Errorf("root %s: %w", name, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("root %s: %q is not a folder", name, dir)
	}
	return name, filepath.Clean(dir), nil
}

// wrongNode is a local artifact on another node: the job was placed on the
// wrong machine, so the runner gives it back rather than failing it.
type wrongNode struct{ want, have string }

func (e *wrongNode) Error() string {
	return fmt.Sprintf("local artifact on node %q, this runner is on %q", e.want, e.have)
}

// resolvePlace returns where a place lies on this node, once the root shows it
// exists inside that root.
func (r *Runner) resolvePlace(p artifact.Place) (string, os.FileInfo, error) {
	if err := p.Validate(); err != nil {
		return "", nil, err
	}
	if p.Node != r.cfg.Node {
		return "", nil, &wrongNode{want: p.Node, have: r.cfg.Node}
	}
	dir, ok := r.cfg.Roots[p.Root]
	if !ok {
		return "", nil, fmt.Errorf("root %q is not installed on this runner", p.Root)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", nil, fmt.Errorf("root %q: %w", p.Root, err)
	}
	defer root.Close()
	info, err := root.Stat(p.Path) // follows links only while they stay inside the root
	if err != nil {
		return "", nil, fmt.Errorf("root %q: %w", p.Root, err)
	}
	return filepath.Join(dir, filepath.FromSlash(p.Path)), info, nil
}

// localInputs returns where each local input of inv lies on this node.
func (r *Runner) localInputs(inv *artifact.Invocation) (map[string]string, error) {
	paths := map[string]string{}
	for name, in := range inv.Inputs {
		if in.Kind != artifact.KindLocal {
			continue
		}
		path, _, err := r.resolvePlace(in.Place)
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", name, err)
		}
		paths[name] = path
	}
	return paths, nil
}

// keepLocalOutput reports a place the compute named as an output: its root
// must be installed here and the place must exist inside it. Its size is a
// file's; a folder's files are not walked.
func (r *Runner) keepLocalOutput(place LocalOutput) (artifact.Output, error) {
	p := artifact.Place{Node: r.cfg.Node, Root: place.Root, Path: place.Path}
	_, info, err := r.resolvePlace(p)
	if err != nil {
		return artifact.Output{}, violation("local output: %v", err)
	}
	size := int64(0)
	switch {
	case info.Mode().IsRegular():
		size = info.Size()
	case info.IsDir():
	default:
		return artifact.Output{}, violation("local output %s/%s is not a regular file or a folder", place.Root, place.Path)
	}
	return artifact.Output{Kind: artifact.KindLocal, Size: size, Place: p}, nil
}

// NamedOutput is one output a compute names in its result: a path under
// outputs/, which the runner uploads, or a place under one of this runner's
// roots, which stays where it is.
type NamedOutput struct {
	Path  string
	Local *LocalOutput
}

// LocalOutput is the {root, path} form of a named output.
type LocalOutput struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

func (o *NamedOutput) UnmarshalJSON(b []byte) error {
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte(`"`)) {
		return json.Unmarshal(b, &o.Path)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	var place LocalOutput
	if err := decoder.Decode(&place); err != nil {
		return fmt.Errorf("output: want a path under outputs/ or {root, path}: %w", err)
	}
	if place.Root == "" || place.Path == "" {
		return errors.New("output: a local output needs root and path")
	}
	o.Local = &place
	return nil
}

func (o NamedOutput) MarshalJSON() ([]byte, error) {
	if o.Local != nil {
		return json.Marshal(o.Local)
	}
	return json.Marshal(o.Path)
}
