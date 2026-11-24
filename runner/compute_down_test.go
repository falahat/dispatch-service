package runner_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/falahat/dispatch-service/runner"
)

// logLines collects a runner's log, so a test can wait for what the runner said.
type logLines struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *logLines) waitFor(t *testing.T, what string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		l.mu.Lock()
		said := strings.Contains(l.text.String(), what)
		l.mu.Unlock()
		if said {
			return
		}
	}
	t.Fatalf("the runner never said %q", what)
}

// startEchoRunner runs a runner against the dispatcher, the CAS and the compute
// given, and returns what it says.
func startEchoRunner(t *testing.T, dispatcherAddr, casURL, computeURL string) *logLines {
	t.Helper()
	said := &logLines{}
	rn := runner.New(runner.Config{
		RunnerID: "Rdown", Node: "n1", Version: "runner/test",
		DispatcherAddr: dispatcherAddr, CASBaseURL: casURL,
		ComputeAddr: strings.TrimPrefix(computeURL, "http://"),
		WorkRoot:    t.TempDir(), Lanes: []string{"embed"}, Capacity: 1, LeaseWaitS: 2,
	}, nil, nil, slog.New(slog.NewTextHandler(said, nil)))
	ctx, stop := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = rn.Run(ctx)
	}()
	t.Cleanup(func() {
		stop()
		<-stopped
	})
	said.waitFor(t, "runner up")
	return said
}

// enqueueEcho enqueues an echo job with one input and returns its id.
func enqueueEcho(t *testing.T, app *appClient, cas *stubCAS, key string) string {
	t.Helper()
	inv, _ := json.Marshal(artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "echo", OpVersion: 1, Params: json.RawMessage(`{}`),
		Inputs: map[string]artifact.Input{"data": {Address: cas.put([]byte("some input")), Kind: artifact.KindBlob}},
	})
	enqueued, err := wire.DecodeBody[wire.EnqueueResult](app.call("e-"+key, wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: key, Lane: "embed", InvocationAddress: cas.put(inv)},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	return enqueued.Results[0].JobID
}

func jobView(t *testing.T, app *appClient, jobID string) wire.JobView {
	t.Helper()
	view, err := wire.DecodeBody[wire.JobView](app.call("j-"+jobID, "job", map[string]string{"job_id": jobID}))
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// A runner whose compute is down or warming up takes no job until the compute is
// ready again. It used to lease job after job and fail each at its invoke as fatal,
// so one dead compute failed the whole queue.
func TestRunnerTakesNoWorkWhileItsComputeIsDown(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	var down atomic.Bool
	echo := echoComputeHandler()
	computeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		echo.ServeHTTP(w, r)
	}))
	defer computeSrv.Close()
	said := startEchoRunner(t, srv.RunnerAddr(), casSrv.URL, computeSrv.URL)

	down.Store(true)
	said.waitFor(t, "compute not ready; taking no work until it is")
	app := dialApp(t, srv.AppAddr())
	jobID := enqueueEcho(t, app, cas, "down-k")
	time.Sleep(2 * time.Second) // the loop asks the compute again each second
	if view := jobView(t, app, jobID); view.State != "QUEUED" {
		t.Fatalf("job is %s (%q) while its compute is down; want QUEUED", view.State, view.Reason)
	}

	down.Store(false)
	said.waitFor(t, "compute ready; taking work again")
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if jobView(t, app, jobID).State == "PERSISTING" {
			return
		}
	}
	t.Fatalf("job never ran once its compute was back: %+v", jobView(t, app, jobID))
}

// A compute that goes down between the lease and the invoke leaves its job to the
// lease: the invoke never reached the compute, so the job did not fail. Its lease
// expires and it runs again. The runner used to fail it as fatal "invoke transport".
func TestJobWhoseComputeIsGoneIsLeftToItsLease(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	computeSrv := httptest.NewServer(echoComputeHandler())
	defer computeSrv.Close()
	// The runner reads the job's invocation after the lease and before the invoke:
	// the compute stops listening right then.
	var gone sync.Once
	blobs := cas.handler()
	casSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gone.Do(func() { computeSrv.Listener.Close() })
		}
		blobs.ServeHTTP(w, r)
	}))
	defer casSrv.Close()
	said := startEchoRunner(t, srv.RunnerAddr(), casSrv.URL, computeSrv.URL)

	app := dialApp(t, srv.AppAddr())
	jobID := enqueueEcho(t, app, cas, "gone-k")
	said.waitFor(t, "compute unreachable; leaving the job to its lease")
	view := jobView(t, app, jobID)
	if view.State != "RUNNING" {
		t.Fatalf("job is %s (%q) after its compute went away; want RUNNING until its lease expires", view.State, view.Reason)
	}
	for _, step := range view.Timeline {
		if step.Outcome != "enqueue" && step.Outcome != "claimed" {
			t.Fatalf("the runner reported %q for a job its compute never saw (%+v)", step.Outcome, view.Timeline)
		}
	}
	said.waitFor(t, "compute not ready; taking no work until it is")
}
