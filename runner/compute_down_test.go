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

// A compute that goes down between the lease and the invoke sends its job straight
// back to the queue: the invoke never reached the compute, so the job did not fail,
// and it is released as interrupted on the same attempt. The runner used to fail it
// as fatal "invoke transport", then left it to its lease, which used up an attempt.
func TestAJobWhoseComputeIsGoneGoesBackToTheQueue(t *testing.T) {
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
	view := jobView(t, app, jobID)
	for deadline := time.Now().Add(20 * time.Second); view.ReleaseCount == 0; view = jobView(t, app, jobID) {
		if time.Now().After(deadline) {
			t.Fatalf("the job was never released after its compute went away: %+v", view)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if view.State != "QUEUED" || view.Attempt != 1 || view.ReleaseCount != 1 {
		t.Fatalf("job is %s on attempt %d after %d releases; want QUEUED on attempt 1 after 1 (%+v)",
			view.State, view.Attempt, view.ReleaseCount, view.Timeline)
	}
	if last := view.Timeline[len(view.Timeline)-1]; last.Outcome != "release" || last.Reason != "interrupted" {
		t.Fatalf("the runner reported %q (%q) for a job its compute never saw; want a release as interrupted", last.Outcome, last.Reason)
	}
	said.waitFor(t, "compute not ready; taking no work until it is")
}

// A compute that takes an invoke and drops it, before answering or partway through
// its answer, died or was restarted mid-job, perhaps because of the job. The job
// fails as unknown and runs again within its max_attempts. It used to fail as
// fatal, which ends a job for good.
func TestAJobWhoseComputeDroppedItRunsAgain(t *testing.T) {
	for name, answered := range map[string]string{
		"before answering": "",
		"mid-answer":       "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n{\"outputs\":",
	} {
		t.Run(name, func(t *testing.T) {
			srv := startDispatcher(t)
			cas := newStubCAS()
			casSrv := httptest.NewServer(cas.handler())
			defer casSrv.Close()
			echo := echoComputeHandler()
			computeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/invoke" {
					echo.ServeHTTP(w, r)
					return
				}
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_, _ = conn.Write([]byte(answered))
					conn.Close()
				}
			}))
			defer computeSrv.Close()
			startEchoRunner(t, srv.RunnerAddr(), casSrv.URL, computeSrv.URL)

			app := dialApp(t, srv.AppAddr())
			jobID := enqueueEcho(t, app, cas, "dropped-k")
			for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
				view := jobView(t, app, jobID)
				for _, step := range view.Timeline {
					if step.Outcome != "fail" {
						continue
					}
					if step.ErrorClass != "unknown" || view.State == "FAILED" {
						t.Fatalf("a dropped invoke failed its job as %q and left it %s; want unknown, to run again", step.ErrorClass, view.State)
					}
					return
				}
			}
			t.Fatalf("the job never failed its dropped invoke: %+v", jobView(t, app, jobID))
		})
	}
}
