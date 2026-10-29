package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommandProgressOptionalAtomicSnapshot(t *testing.T) {
	root := t.TempDir()
	r := New(Config{Command: []string{"executor"}, WorkRoot: root}, nil, nil, nil)
	if data, err := r.commandProgress("job"); err != nil || data != nil {
		t.Fatalf("progress is optional: %s %v", data, err)
	}
	if err := os.Mkdir(filepath.Join(root, "job"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []string{`{"stage":"first"}`, `{"stage":"second","completed":1}`} {
		temporary := filepath.Join(root, "job", "next.json")
		if err := os.WriteFile(temporary, []byte(snapshot), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, filepath.Join(root, "job", "invoke-progress.json")); err != nil {
			t.Fatal(err)
		}
		if data, err := r.commandProgress("job"); err != nil || string(data) != snapshot {
			t.Fatalf("latest executor snapshot: %s %v", data, err)
		}
	}
}
