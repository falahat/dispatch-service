package runner_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/runner"
)

// TestStoppingRunnerLeavesItsJobLeased stops a runner (its SIGTERM: a reboot, or a
// compute restart that stops the runner with it) while its job is inside the invoke.
// The cut-short invoke says nothing about the job, so the runner reports nothing: the
// job stays RUNNING on its lease, which expires, and the job runs again. Reporting it
// as fail{fatal} used to dead-letter every job a reboot interrupted.
func TestStoppingRunnerLeavesItsJobLeased(t *testing.T) {
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
	if view.State != "RUNNING" {
		t.Fatalf("job is %s after its runner stopped; want RUNNING until its lease expires (reason %q)", view.State, view.Reason)
	}
	for _, step := range view.Timeline {
		if step.Outcome != "enqueue" && step.Outcome != "claimed" {
			t.Fatalf("the stopping runner reported %q for its job (%+v)", step.Outcome, view.Timeline)
		}
	}
}
