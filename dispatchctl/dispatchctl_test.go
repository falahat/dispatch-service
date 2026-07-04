package main

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

// startServer boots a real in-process dispatcher on loopback TCP (both
// surfaces) and returns its app-surface address. Zero mocks: the CLI's framed
// client drives the same wire path a production dispatchctl would.
func startServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	store, err := dispatcher.OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := dispatcher.DefaultConfig()
	cfg.RunnerListen = "127.0.0.1:0"
	cfg.AppSocket = ""
	cfg.AppListen = "127.0.0.1:0"
	cfg.MaxWaitS = 2
	cfg.Budget.CapUSD = "100.00"

	d, err := dispatcher.New(store, cfg, dispatcher.RealClock)
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	srv := dispatcher.NewServer(d, slog.New(slog.NewTextHandler(discard{}, nil)))
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv.AppAddr()
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func dialTest(t *testing.T, addr string) *client {
	t.Helper()
	c, err := dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.close() })
	return c
}

func invAddr(s string) artifact.Address { return artifact.ComputeAddress([]byte(s)) }

// TestEnqueueListCancel drives the CLI's client end to end: enqueue a job, list
// jobs and find it, cancel it, and re-list to see the terminal state — asserting
// the reply types the CLI relies on.
func TestEnqueueListCancel(t *testing.T) {
	c := dialTest(t, startServer(t))
	inv := invAddr("job-one")

	// enqueue
	env, err := c.call(wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "k-one", Lane: "embed", InvocationAddress: inv},
	}})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if env.Type != wire.TypeEnqueueResult {
		t.Fatalf("enqueue reply type %q", env.Type)
	}
	er, err := wire.DecodeBody[enqueueResult](env)
	if err != nil {
		t.Fatalf("decode enqueue: %v", err)
	}
	if len(er.Results) != 1 || !er.Results[0].Created {
		t.Fatalf("enqueue result %+v", er.Results)
	}
	jobID := er.Results[0].JobID

	// list + find via the CLI helper
	res, err := fetchJobs(c, jobsRequest{})
	if err != nil {
		t.Fatalf("jobs: %v", err)
	}
	if !hasJob(res, jobID) {
		t.Fatalf("job %s not in listing %+v", jobID, res.Jobs)
	}
	j, err := findJob(c, jobID)
	if err != nil {
		t.Fatalf("findJob: %v", err)
	}
	if j.State != "QUEUED" || j.Lane != "embed" || j.JobKey != "k-one" {
		t.Fatalf("unexpected job view %+v", j)
	}
	// The enqueue attempt must be on the timeline (trace's raw material).
	if len(j.Timeline) == 0 {
		t.Fatalf("expected a non-empty timeline")
	}

	// cancel
	env, err = c.call(wire.TypeCancel, wire.Cancel{JobID: jobID, Reason: "test"})
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if env.Type != wire.TypeOK {
		t.Fatalf("cancel reply type %q", env.Type)
	}

	// re-fetch: job is now CANCELLED
	j, err = findJob(c, jobID)
	if err != nil {
		t.Fatalf("findJob after cancel: %v", err)
	}
	if j.State != "CANCELLED" {
		t.Fatalf("state after cancel = %q, want CANCELLED", j.State)
	}

	// render paths should not panic and should mention the job.
	if out := renderJobs(res); !strings.Contains(out, jobID) {
		t.Fatalf("renderJobs missing job id:\n%s", out)
	}
	if out := renderTimeline(j); !strings.Contains(out, "enqueued") {
		t.Fatalf("renderTimeline missing enqueued line:\n%s", out)
	}
}

// TestJobsFilter checks the filter/page request shape reaches the dispatcher and
// narrows results.
func TestJobsFilter(t *testing.T) {
	c := dialTest(t, startServer(t))
	mustEnqueue(t, c, "a", "embed", invAddr("a"))
	mustEnqueue(t, c, "b", "transcribe", invAddr("b"))

	res, err := fetchJobs(c, jobsRequest{Filter: &jobsFilterWire{Lane: "transcribe"}})
	if err != nil {
		t.Fatalf("jobs filter: %v", err)
	}
	if len(res.Jobs) != 1 || res.Jobs[0].Lane != "transcribe" {
		t.Fatalf("lane filter returned %+v", res.Jobs)
	}

	res, err = fetchJobs(c, jobsRequest{Filter: &jobsFilterWire{JobKeyPrefix: "a"}})
	if err != nil {
		t.Fatalf("jobs prefix: %v", err)
	}
	if len(res.Jobs) != 1 || res.Jobs[0].JobKey != "a" {
		t.Fatalf("prefix filter returned %+v", res.Jobs)
	}
}

// TestFleetBudgetSweep asserts the snapshot verbs return their result types and
// decode cleanly.
func TestFleetBudgetSweep(t *testing.T) {
	c := dialTest(t, startServer(t))

	fenv, err := c.call(wire.TypeFleet, struct{}{})
	if err != nil {
		t.Fatalf("fleet: %v", err)
	}
	if fenv.Type != "fleet_result" {
		t.Fatalf("fleet reply type %q", fenv.Type)
	}
	if _, err := wire.DecodeBody[fleetResult](fenv); err != nil {
		t.Fatalf("decode fleet: %v", err)
	}

	benv, err := c.call(wire.TypeBudget, struct{}{})
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	if benv.Type != "budget_result" {
		t.Fatalf("budget reply type %q", benv.Type)
	}
	b, err := wire.DecodeBody[budgetView](benv)
	if err != nil {
		t.Fatalf("decode budget: %v", err)
	}
	if b.CapUSD != "100.00" {
		t.Fatalf("budget cap = %q, want 100.00", b.CapUSD)
	}

	senv, err := c.call(wire.TypeSweep, struct{}{})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if senv.Type != "sweep_result" {
		t.Fatalf("sweep reply type %q", senv.Type)
	}
	if _, err := wire.DecodeBody[sweepResult](senv); err != nil {
		t.Fatalf("decode sweep: %v", err)
	}
}

// TestStats drives the drain-health verb end to end: enqueue two jobs, cancel
// one, then assert the reply type, the (lane, state) counts, the windowed
// cancel event, and that the renderer shows the verdict line.
func TestStats(t *testing.T) {
	c := dialTest(t, startServer(t))
	mustEnqueue(t, c, "a", "embed", invAddr("a"))
	cancelled := mustEnqueue(t, c, "b", "transcribe", invAddr("b"))
	if _, err := c.call(wire.TypeCancel, wire.Cancel{JobID: cancelled, Reason: "test"}); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	env, err := c.call(wire.TypeStats, statsRequest{})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if env.Type != "stats_result" {
		t.Fatalf("stats reply type %q", env.Type)
	}
	v, err := wire.DecodeBody[statsView](env)
	if err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if v.WindowS != 900 {
		t.Fatalf("default window = %d, want 900", v.WindowS)
	}
	counts := map[string]int{}
	for _, j := range v.Jobs {
		counts[j.Lane+"/"+j.State] = j.Count
	}
	if counts["embed/QUEUED"] != 1 || counts["transcribe/CANCELLED"] != 1 {
		t.Fatalf("job counts = %v", counts)
	}
	var sawCancel bool
	for _, a := range v.Attempts {
		if a.Lane == "transcribe" && a.Outcome == "cancel" && a.Count == 1 {
			sawCancel = true
		}
	}
	if !sawCancel {
		t.Fatalf("windowed cancel event missing: %+v", v.Attempts)
	}
	if v.OldestQueuedAgeS < 0 {
		t.Fatalf("oldest queued age = %d", v.OldestQueuedAgeS)
	}
	out := renderStats(v)
	if !strings.Contains(out, "drain (15m):") || !strings.Contains(out, "QUEUED") {
		t.Fatalf("renderStats output:\n%s", out)
	}
}

// TestErrorReplyIsError verifies an `error` reply is surfaced as a Go error
// (so the CLI exits non-zero) rather than swallowed.
func TestErrorReplyIsError(t *testing.T) {
	c := dialTest(t, startServer(t))
	// A malformed job_id makes Cancel fail with error{invalid}.
	_, err := c.call(wire.TypeCancel, wire.Cancel{JobID: "not-a-ulid", Reason: "x"})
	if err == nil {
		t.Fatalf("expected an error reply, got nil")
	}
	var we wire.Error
	if !asWireError(err, &we) {
		t.Fatalf("expected a *wire.Error, got %T: %v", err, err)
	}
	if we.Code != wire.CodeInvalid {
		t.Fatalf("error code = %q, want %q", we.Code, wire.CodeInvalid)
	}
}

// TestParseAddr covers the unix/tcp addressing split the client dials on.
func TestParseAddr(t *testing.T) {
	cases := []struct{ in, net, target string }{
		{"unix:/tmp/d.sock", "unix", "/tmp/d.sock"},
		{"127.0.0.1:7701", "tcp", "127.0.0.1:7701"},
		{"localhost:9999", "tcp", "localhost:9999"},
	}
	for _, tc := range cases {
		n, tgt := parseAddr(tc.in)
		if n != tc.net || tgt != tc.target {
			t.Errorf("parseAddr(%q) = (%q,%q), want (%q,%q)", tc.in, n, tgt, tc.net, tc.target)
		}
	}
}

// --- helpers ---

func mustEnqueue(t *testing.T, c *client, key, lane string, inv artifact.Address) string {
	t.Helper()
	env, err := c.call(wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: key, Lane: lane, InvocationAddress: inv},
	}})
	if err != nil {
		t.Fatalf("enqueue %s: %v", key, err)
	}
	er, err := wire.DecodeBody[enqueueResult](env)
	if err != nil || len(er.Results) != 1 {
		t.Fatalf("enqueue %s result: %+v err=%v", key, er, err)
	}
	return er.Results[0].JobID
}

func hasJob(res jobsResult, jobID string) bool {
	for _, j := range res.Jobs {
		if j.JobID == jobID {
			return true
		}
	}
	return false
}

// asWireError extracts a wire.Error from err (the client returns it by value as
// the error interface).
func asWireError(err error, out *wire.Error) bool {
	if we, ok := err.(wire.Error); ok {
		*out = we
		return true
	}
	return false
}
