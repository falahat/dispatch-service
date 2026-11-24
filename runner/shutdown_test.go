package runner_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/runner"
)

// TestAStoppingRunnerGivesItsJobBack stops a runner (its SIGTERM: a reboot or a
// release) while its job is inside the invoke. The cut-short invoke says nothing
// about the job, so the runner releases it as interrupted, and the job is queued
// again at once on the same attempt. Left to its lease, it waited out the TTL and
// used up an attempt, and on its last one failed as lease_expired; reported as
// fail{fatal}, it was dead-lettered.
func TestAStoppingRunnerGivesItsJobBack(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	invoked := make(chan struct{})
	release := make(chan struct{})
	computeSrv := httptest.NewServer(blockingComputeHandler(invoked, release))
	defer computeSrv.Close()
	defer close(release) // before the compute server closes: its invoke handler waits on it

	app := dialApp(t, srv.AppAddr())
	jobID := enqueueEcho(t, app, cas, "stop-k")
	rn := runner.New(runner.Config{
		RunnerID: "Rstop", Node: "n1", Version: "runner/test",
		DispatcherAddr: srv.RunnerAddr(), CASBaseURL: casSrv.URL,
		ComputeAddr: strings.TrimPrefix(computeSrv.URL, "http://"),
		WorkRoot:    t.TempDir(), Lanes: []string{"embed"}, Capacity: 1, LeaseWaitS: 2,
	}, nil, nil, nil)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopped := make(chan error, 1)
	go func() { stopped <- rn.Run(ctx) }()
	select {
	case <-invoked:
	case <-time.After(20 * time.Second):
		t.Fatal("the job never reached its compute")
	}

	stop()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("runner stopped with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the runner did not stop")
	}

	view := jobView(t, app, jobID)
	if view.State != "QUEUED" || view.Attempt != 1 || view.ReleaseCount != 1 {
		t.Fatalf("job is %s on attempt %d after %d releases once its runner stopped; want QUEUED on attempt 1 after 1 (%+v)",
			view.State, view.Attempt, view.ReleaseCount, view.Timeline)
	}
	if last := view.Timeline[len(view.Timeline)-1]; last.Outcome != "release" || last.Reason != "interrupted" {
		t.Fatalf("the stopping runner reported %q (%q); want a release as interrupted", last.Outcome, last.Reason)
	}
}
