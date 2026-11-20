package runner_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/falahat/dispatch-service/runner"
)

// folderComputeHandler writes one file output and one folder output.
func folderComputeHandler(files map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "op": "spool", "op_version": 1})
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		var req runner.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(500)
			return
		}
		for rel, content := range files {
			path := filepath.Join(req.Workdir, req.OutputsDir, filepath.FromSlash(rel))
			os.MkdirAll(filepath.Dir(path), 0o755)
			os.WriteFile(path, []byte(content), 0o644)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"outputs": map[string]string{"report": "outputs/report.json", "spool": "outputs/spool"},
			"metrics": map[string]int64{},
		})
	})
	return mux
}

// TestFolderOutputPublishesManifest checks that a folder output arrives as a
// manifest of its files, in path order, each file stored in the CAS.
func TestFolderOutputPublishesManifest(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	files := map[string]string{
		"report.json":       `{"ok":true}`,
		"spool/frame-1.bin": "first frame",
		"spool/maps/n1.bin": "normals",
		"spool/frame-0.bin": "zeroth frame",
	}
	computeSrv := httptest.NewServer(folderComputeHandler(files))
	defer computeSrv.Close()

	invBytes, _ := json.Marshal(artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "spool", OpVersion: 1,
		Params: json.RawMessage(`{}`), Inputs: map[string]artifact.Input{},
	})
	invAddr := cas.put(invBytes)
	app := dialApp(t, srv.AppAddr())
	env := app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "folder-k", Lane: "embed", InvocationAddress: invAddr},
	}})
	enqueued, _ := wire.DecodeBody[wire.EnqueueResult](env)
	jobID := enqueued.Results[0].JobID

	rn := runner.New(runner.Config{
		RunnerID: "Rfolder", Node: "n1", Version: "runner/test",
		DispatcherAddr: srv.RunnerAddr(), CASBaseURL: casSrv.URL,
		ComputeAddr: strings.TrimPrefix(computeSrv.URL, "http://"),
		WorkRoot:    t.TempDir(), Lanes: []string{"embed"}, Capacity: 1, LeaseWaitS: 2,
	}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rn.Run(ctx)

	waited := app.call("w1", "wait", map[string]string{"job_id": jobID})
	view, err := wire.DecodeBody[wire.JobView](waited)
	if err != nil || view.State != "PERSISTING" {
		t.Fatalf("job did not reach PERSISTING: %v %s", err, waited.Body)
	}
	var result artifact.ActionResult
	if err := json.Unmarshal(view.ActionResult, &result); err != nil {
		t.Fatal(err)
	}

	report := result.Outputs["report"]
	if report.Kind != artifact.KindBlob || report.Address != artifact.ComputeAddress([]byte(files["report.json"])) {
		t.Fatalf("file output = %+v", report)
	}
	spool := result.Outputs["spool"]
	if spool.Kind != artifact.KindManifest {
		t.Fatalf("folder output kind = %q", spool.Kind)
	}
	cas.mu.Lock()
	body := cas.blobs[spool.Address.Hex()]
	cas.mu.Unlock()
	if int64(len(body)) != spool.Size {
		t.Fatalf("manifest size %d, output says %d", len(body), spool.Size)
	}
	var manifest artifact.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil || manifest.Validate() != nil {
		t.Fatalf("manifest %s: %v", body, err)
	}
	want := []string{"frame-0.bin", "frame-1.bin", "maps/n1.bin"}
	if len(manifest.Entries) != len(want) {
		t.Fatalf("manifest entries %+v", manifest.Entries)
	}
	for i, entry := range manifest.Entries {
		content := files["spool/"+want[i]]
		if entry.Path != want[i] || entry.Size != int64(len(content)) || entry.Address != artifact.ComputeAddress([]byte(content)) {
			t.Fatalf("entry %d = %+v, want %s", i, entry, want[i])
		}
		cas.mu.Lock()
		stored := string(cas.blobs[entry.Address.Hex()])
		cas.mu.Unlock()
		if stored != content {
			t.Fatalf("entry %s not stored: %q", entry.Path, stored)
		}
	}
}
