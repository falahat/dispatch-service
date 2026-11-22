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

// inPlaceCompute reads its local input where it lies, writes a new folder under
// the root its request names and names that folder as a local output, plus one
// ordinary output.
func inPlaceCompute(t *testing.T, root string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "op": "stage", "op_version": 1})
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		var req runner.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(500)
			return
		}
		if req.Inputs["run"] != filepath.Join(root, "K") {
			t.Errorf("local input handed over as %q, want it where it lies", req.Inputs["run"])
		}
		if req.Roots["runs"] != root {
			t.Errorf("request names roots %v, want runs at %q", req.Roots, root)
		}
		given, _ := os.ReadFile(filepath.Join(req.Inputs["run"], "in.txt"))
		os.MkdirAll(filepath.Join(req.Roots["runs"], "K", "fit"), 0o755)
		os.WriteFile(filepath.Join(req.Roots["runs"], "K", "fit", "out.txt"), append([]byte("made from "), given...), 0o644)
		os.WriteFile(filepath.Join(req.Workdir, req.OutputsDir, "report.json"), []byte(`{"ok":true}`), 0o644)
		json.NewEncoder(w).Encode(map[string]any{
			"outputs": map[string]any{"kept": map[string]string{"root": "runs", "path": "K/fit"}, "report": "outputs/report.json"},
			"metrics": map[string]int64{},
		})
	})
	return mux
}

func runLocalJob(t *testing.T, input artifact.Place) (wire.JobView, *stubCAS, string) {
	t.Helper()
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	t.Cleanup(casSrv.Close)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "K"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "K", "in.txt"), []byte("the clip"), 0o644); err != nil {
		t.Fatal(err)
	}
	computeSrv := httptest.NewServer(inPlaceCompute(t, root))
	t.Cleanup(computeSrv.Close)

	invBytes, _ := json.Marshal(artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "stage", OpVersion: 1, Params: json.RawMessage(`{}`),
		Inputs: map[string]artifact.Input{"run": {Kind: artifact.KindLocal, Place: input}},
	})
	app := dialApp(t, srv.AppAddr())
	node := input.Node
	env := app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "local-k", Lane: "embed", InvocationAddress: cas.put(invBytes), Policy: &wire.Policy{Node: &node}},
	}})
	enqueued, _ := wire.DecodeBody[wire.EnqueueResult](env)
	rn := runner.New(runner.Config{
		RunnerID: "Rlocal", Node: "n1", Version: "runner/test",
		DispatcherAddr: srv.RunnerAddr(), CASBaseURL: casSrv.URL,
		ComputeAddr: strings.TrimPrefix(computeSrv.URL, "http://"),
		WorkRoot:    t.TempDir(), Lanes: []string{"embed"}, Capacity: 1, LeaseWaitS: 2,
		Roots: map[string]string{"runs": root},
	}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go rn.Run(ctx)
	waited := app.call("w1", "wait", map[string]string{"job_id": enqueued.Results[0].JobID})
	view, err := wire.DecodeBody[wire.JobView](waited)
	if err != nil {
		t.Fatal(err)
	}
	return view, cas, root
}

// A job on a local input reads it where it lies and keeps its local output
// there: only the invocation and the ordinary output reach the CAS.
func TestLocalArtifactsStayWhereTheyLie(t *testing.T) {
	view, cas, root := runLocalJob(t, artifact.Place{Node: "n1", Root: "runs", Path: "K"})
	if view.State != "PERSISTING" {
		t.Fatalf("job did not reach PERSISTING: %+v", view)
	}
	var result artifact.ActionResult
	if err := json.Unmarshal(view.ActionResult, &result); err != nil {
		t.Fatal(err)
	}
	made, _ := os.ReadFile(filepath.Join(root, "K", "fit", "out.txt"))
	kept := result.Outputs["kept"]
	want := artifact.Output{Kind: artifact.KindLocal, Place: artifact.Place{Node: "n1", Root: "runs", Path: "K/fit"}}
	if string(made) != "made from the clip" || kept != want {
		t.Fatalf("local output = %+v (%q), want %+v", kept, made, want)
	}
	if report := result.Outputs["report"]; report.Kind != artifact.KindBlob || report.Address != artifact.ComputeAddress([]byte(`{"ok":true}`)) {
		t.Fatalf("ordinary output = %+v", report)
	}
	cas.mu.Lock()
	defer cas.mu.Unlock()
	for hex, body := range cas.blobs {
		if strings.Contains(string(body), "the clip") {
			t.Fatalf("a local file's bytes reached the CAS as %s", hex)
		}
	}
	if len(cas.blobs) != 2 {
		t.Fatalf("the CAS holds %d blobs, want the invocation and the report", len(cas.blobs))
	}
}

// A local input under a root this runner was not installed with fails the job
// before the compute runs.
func TestLocalInputUnderAnUnknownRootFails(t *testing.T) {
	view, _, root := runLocalJob(t, artifact.Place{Node: "n1", Root: "trees", Path: "K"})
	if view.State != "FAILED" {
		t.Fatalf("job state %s, want FAILED: %+v", view.State, view)
	}
	if _, err := os.Stat(filepath.Join(root, "K", "fit")); err == nil {
		t.Fatal("the compute ran on a job with an unknown root")
	}
}
