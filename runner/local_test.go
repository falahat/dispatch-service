package runner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/falahat/dispatch-service/internal/artifact"
)

func TestResolvePlaceStaysInsideItsRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	run := filepath.Join(root, "lane", "runs", "K")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Runner{cfg: Config{Node: "bigboi", Roots: map[string]string{"runs": root}}}
	place := func(node, rootName, path string) artifact.Place {
		return artifact.Place{Node: node, Root: rootName, Path: path}
	}

	path, info, err := r.resolvePlace(place("bigboi", "runs", "lane/runs/K"))
	if err != nil || path != run || !info.IsDir() {
		t.Fatalf("resolve = %q %v %v", path, info, err)
	}
	var elsewhere *wrongNode
	if _, _, err := r.resolvePlace(place("laptop", "runs", "lane/runs/K")); !errors.As(err, &elsewhere) {
		t.Fatalf("a place on another node: %v", err)
	}
	for why, p := range map[string]artifact.Place{
		"a root not installed": place("bigboi", "trees", "lane"),
		"a missing path":       place("bigboi", "runs", "lane/runs/L"),
		"a traversal":          place("bigboi", "runs", "lane/../../secret"),
		"an absolute path":     place("bigboi", "runs", filepath.ToSlash(outside)),
		"a dot segment":        place("bigboi", "runs", "lane/./runs"),
	} {
		if _, _, err := r.resolvePlace(p); err == nil || errors.As(err, &elsewhere) {
			t.Errorf("%s was not refused: %v", why, err)
		}
	}

	t.Run("links", func(t *testing.T) {
		if err := os.Symlink(outside, filepath.Join(root, "lane", "leak")); err != nil {
			t.Skipf("this machine makes no symbolic links: %v", err)
		}
		if err := os.Symlink(filepath.Join("runs", "K"), filepath.Join(root, "lane", "latest")); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"lane/leak", "lane/leak/secret"} {
			if _, _, err := r.resolvePlace(place("bigboi", "runs", p)); err == nil {
				t.Errorf("%s leads out of the root and was not refused", p)
			}
		}
		if path, info, err := r.resolvePlace(place("bigboi", "runs", "lane/latest")); err != nil || !info.IsDir() || path != filepath.Join(root, "lane", "latest") {
			t.Errorf("a link that stays inside the root: %q %v", path, err)
		}
	})
}

func TestParseRootTakesANameAndAnExistingFolder(t *testing.T) {
	dir := t.TempDir()
	if name, got, err := ParseRoot("runs=" + dir); err != nil || name != "runs" || got != filepath.Clean(dir) {
		t.Fatalf("ParseRoot = %q %q %v", name, got, err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"runs", "=" + dir, "Runs=" + dir, "runs=relative/dir", "runs=" + filepath.Join(dir, "missing"), "runs=" + file} {
		if _, _, err := ParseRoot(bad); err == nil {
			t.Errorf("ParseRoot(%q) accepted", bad)
		}
	}
}
