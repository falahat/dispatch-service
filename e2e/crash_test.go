package e2e

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	runnerpkg "github.com/falahat/dispatch-service/runner"
)

func appDial(t *testing.T, addr string) net.Conn {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial app: %v", err)
	}
	return c
}

func runnerBin(t *testing.T) string {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(thisFile))
	p := filepath.Join(root, "bin", exeName("runner"))
	if _, err := os.Stat(p); err != nil {
		t.Skipf("runner binary not built (%v); run: go build -o bin/runner ./runner/cmd/runner", err)
	}
	return p
}

// sleepyCompute echoes inputs after a delay, WITHOUT single-flight — so the
// second runner isn't blocked by the first's abandoned invoke.
func sleepyCompute(delay time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "op": "echo", "op_version": 1})
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		var req runnerpkg.InvokeRequest
		json.NewDecoder(r.Body).Decode(&req)
		time.Sleep(delay)
		outDir := filepath.Join(req.Workdir, req.OutputsDir)
		os.MkdirAll(outDir, 0o755)
		outputs := map[string]string{}
		for name, rel := range req.Inputs {
			data, err := os.ReadFile(filepath.Join(req.Workdir, filepath.FromSlash(rel)))
			if err != nil {
				w.WriteHeader(500)
				json.NewEncoder(w).Encode(map[string]string{"error_class": "bad_input", "message": "missing"})
				return
			}
			os.WriteFile(filepath.Join(outDir, name), data, 0o644)
			outputs[name] = filepath.ToSlash(filepath.Join(req.OutputsDir, name))
		}
		json.NewEncoder(w).Encode(map[string]any{"outputs": outputs, "metrics": map[string]int64{"n": 1}})
	})
	return mux
}

func startDispatcherShortLease(t *testing.T) *dispatcher.Server {
	dir := t.TempDir()
	store, err := dispatcher.OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := dispatcher.DefaultConfig()
	cfg.RunnerListen = "127.0.0.1:0"
	cfg.AppListen = "127.0.0.1:0"
	cfg.AppSocket = ""
	cfg.LeaseTTLS = 3          // short so the sweep recovers a dead runner quickly
	cfg.HeartbeatIntervalS = 1 // but a HEALTHY runner renews well within the TTL
	cfg.SweepIntervalS = 1
	cfg.MaxWaitS = 2
	cfg.Lanes = map[string]dispatcher.LaneConfig{"embed": {Concurrency: 4, PersistingWatermark: 64}}
	d, err := dispatcher.New(store, cfg, dispatcher.RealClock)
	if err != nil {
		t.Fatal(err)
	}
	srv := dispatcher.NewServer(d, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func jobStateAttempt(t *testing.T, addr, jobID string) (string, int) {
	env := appCall(t, addr, "q"+jobID[len(jobID)-4:], wire.TypeJobs, map[string]any{})
	var jr struct {
		Jobs []struct {
			JobID   string `json:"job_id"`
			State   string `json:"state"`
			Attempt int    `json:"attempt"`
		} `json:"jobs"`
	}
	json.Unmarshal(env.Body, &jr)
	for _, j := range jr.Jobs {
		if j.JobID == jobID {
			return j.State, j.Attempt
		}
	}
	return "", 0
}

func startRunnerProc(t *testing.T, bin, dispatcherAddr, casURL, computeAddr, id string) *exec.Cmd {
	cmd := exec.Command(bin, "run",
		"-id", id, "-dispatcher", dispatcherAddr, "-cas", casURL,
		"-compute", computeAddr, "-work", t.TempDir(), "-lanes", "embed", "-wait", "2")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	return cmd
}

// TestCrashInjectionRecovers kills a runner mid-job (SIGKILL) and asserts the
// dispatcher's sweep recovers the job and a fresh runner completes it exactly
// once — no lost job, no double-persist.
func TestCrashInjectionRecovers(t *testing.T) {
	bin := runnerBin(t)
	srv := startDispatcherShortLease(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	computeSrv := httptest.NewServer(sleepyCompute(2 * time.Second))
	defer computeSrv.Close()
	computeAddr := strings.TrimPrefix(computeSrv.URL, "http://")

	input := []byte("crash-test bytes")
	dataAddr := cas.put(input)
	inv := artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "echo", OpVersion: 1, Params: json.RawMessage(`{"n":1}`),
		Inputs: map[string]artifact.Input{"data": {Address: dataAddr, Kind: artifact.KindBlob}},
	}
	invBytes, _ := json.Marshal(inv)
	invAddr := cas.put(invBytes)

	env := appCall(t, srv.AppAddr(), "e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "crash-k", Lane: "embed", InvocationAddress: invAddr},
	}})
	er, _ := wire.DecodeBody[wire.EnqueueResult](env)
	jobID := er.Results[0].JobID

	// Runner #1 leases the job and blocks inside invoke.
	r1 := startRunnerProc(t, bin, srv.RunnerAddr(), casSrv.URL, computeAddr, "R1")

	// Wait until the job is RUNNING (attempt 1).
	waitForState(t, srv.AppAddr(), jobID, "RUNNING", 15*time.Second)
	_, att := jobStateAttempt(t, srv.AppAddr(), jobID)
	if att != 1 {
		t.Fatalf("expected attempt 1 while running, got %d", att)
	}

	// SIGKILL the runner mid-job: no complete/fail is ever sent.
	_ = r1.Process.Kill()
	_, _ = r1.Process.Wait()

	// The sweep must recover the orphaned lease: back to QUEUED with attempt 2.
	waitForState(t, srv.AppAddr(), jobID, "QUEUED", 15*time.Second)
	_, att = jobStateAttempt(t, srv.AppAddr(), jobID)
	if att != 2 {
		t.Fatalf("after sweep, expected attempt 2, got %d", att)
	}

	// A fresh runner completes the job.
	r2 := startRunnerProc(t, bin, srv.RunnerAddr(), casSrv.URL, computeAddr, "R2")
	defer func() { _ = r2.Process.Kill(); _, _ = r2.Process.Wait() }()

	waitForState(t, srv.AppAddr(), jobID, "PERSISTING", 20*time.Second)

	// Exactly one completion in the inbox for this job.
	sub := appDial(t, srv.AppAddr())
	defer sub.Close()
	if err := wire.WriteMessage(sub, "s1", wire.TypeSubscribe, wire.Subscribe{}); err != nil {
		t.Fatal(err)
	}
	sub.SetReadDeadline(time.Now().Add(10 * time.Second))
	ce, err := wire.ReadMessage(sub)
	if err != nil {
		t.Fatalf("read completion: %v", err)
	}
	comp, _ := wire.DecodeBody[wire.Completion](ce)
	if comp.JobID != jobID || comp.Attempt != 2 {
		t.Fatalf("unexpected completion: job=%s attempt=%d", comp.JobID, comp.Attempt)
	}

	// Ack -> SUCCEEDED; exactly-once effect.
	appCall(t, srv.AppAddr(), "a1", wire.TypeAck, wire.Ack{JobID: jobID, Disposition: wire.DispositionPersisted})
	st, _ := jobStateAttempt(t, srv.AppAddr(), jobID)
	if st != "SUCCEEDED" {
		t.Fatalf("final state %s, want SUCCEEDED", st)
	}
}

func waitForState(t *testing.T, addr, jobID, want string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, _ := jobStateAttempt(t, addr, jobID)
		if st == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	st, _ := jobStateAttempt(t, addr, jobID)
	t.Fatalf("job %s never reached %s (last state %q)", jobID, want, st)
}
