package dispatcher

import (
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

// findAttempt returns the count for a (lane, outcome) cell, 0 if absent.
func findAttempt(v StatsView, lane, outcome string) int {
	for _, a := range v.Attempts {
		if a.Lane == lane && a.Outcome == outcome {
			return a.Count
		}
	}
	return 0
}

// findJobCount returns the count for a (lane, state) cell, 0 if absent.
func findJobCount(v StatsView, lane, state string) int {
	for _, j := range v.Jobs {
		if j.Lane == lane && j.State == state {
			return j.Count
		}
	}
	return 0
}

// TestStatsSnapshot drives a real lifecycle (enqueue -> claim -> complete/fail
// -> ack) across a manual clock and asserts the drain-health snapshot: state
// counts, windowed attempt outcomes, grouped failure reasons, and the oldest
// QUEUED age. The window must exclude old events — the whole point is "is it
// draining NOW", not "did it ever drain".
func TestStatsSnapshot(t *testing.T) {
	d, clk := newTestDispatcher(t)
	t0 := clk.NowMS()

	jobA := enqueueOne(t, d, "ka", "transcribe", invAddr("a"), nil)
	clk.Set(t0 + 1_000)
	jobB := enqueueOne(t, d, "kb", "transcribe", invAddr("b"), nil)
	clk.Set(t0 + 2_000)
	enqueueOne(t, d, "kc", "embed", invAddr("c"), nil)
	hello(t, d, "R1", "transcribe")

	// jobA: claim -> complete -> ack persisted (SUCCEEDED), all at t0+2s.
	g, _ := leaseOne(t, d, "R1", "transcribe")
	if g == nil || g.Job.JobID != jobA {
		t.Fatalf("expected grant for %s, got %+v", jobA, g)
	}
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: jobA, Attempt: 1, ActionResult: sampleResult(invAddr("a"))}); werr != nil {
		t.Fatalf("complete: %v", werr)
	}
	if werr := d.Ack(wire.Ack{JobID: jobA, Disposition: wire.DispositionPersisted}); werr != nil {
		t.Fatalf("ack: %v", werr)
	}

	// Jump past the default window, then jobB: claim -> terminal fail.
	clk.Set(t0 + 950_000)
	g2, _ := leaseOne(t, d, "R1", "transcribe")
	if g2 == nil || g2.Job.JobID != jobB {
		t.Fatalf("expected grant for %s, got %+v", jobB, g2)
	}
	if werr := d.Fail("R1", wire.Fail{LeaseID: g2.Lease.LeaseID, JobID: jobB, Attempt: 1, ErrorClass: wire.ClassBadInput, Message: "bad audio"}); werr != nil {
		t.Fatalf("fail: %v", werr)
	}

	v, err := d.Stats(StatsRequest{})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if v.WindowS != statsWindowDefaultS {
		t.Fatalf("window = %d, want default %d", v.WindowS, statsWindowDefaultS)
	}
	// States: the full queue picture regardless of window.
	for _, want := range []struct {
		lane, state string
		count       int
	}{
		{"transcribe", "SUCCEEDED", 1},
		{"transcribe", "FAILED", 1},
		{"embed", "QUEUED", 1},
	} {
		if got := findJobCount(v, want.lane, want.state); got != want.count {
			t.Fatalf("jobs[%s,%s] = %d, want %d (%+v)", want.lane, want.state, got, want.count, v.Jobs)
		}
	}
	// Window: only jobB's fail is recent; jobA's complete/ack and all the
	// enqueues happened ~950s ago and must be excluded.
	if got := findAttempt(v, "transcribe", "fail"); got != 1 {
		t.Fatalf("attempts[transcribe,fail] = %d, want 1 (%+v)", got, v.Attempts)
	}
	if len(v.Attempts) != 1 {
		t.Fatalf("attempts outside the window leaked in: %+v", v.Attempts)
	}
	// Failure grouping carries the class + reason — the "why" column.
	if len(v.RecentFailures) != 1 {
		t.Fatalf("recent_failures = %+v, want exactly one row", v.RecentFailures)
	}
	f := v.RecentFailures[0]
	if f.Lane != "transcribe" || f.ErrorClass != "bad_input" || f.Reason != "bad audio" || f.Count != 1 {
		t.Fatalf("recent failure row = %+v", f)
	}
	// The embed job has been QUEUED since t0+2s -> 948s old at t0+950s.
	if v.OldestQueuedAgeS != 948 {
		t.Fatalf("oldest_queued_age_s = %d, want 948", v.OldestQueuedAgeS)
	}
}

// TestStatsWindowClamp asks for an absurd window and expects the cap to bite:
// events older than the capped window stay excluded, fresh ones count.
func TestStatsWindowClamp(t *testing.T) {
	d, clk := newTestDispatcher(t)
	t0 := clk.NowMS()

	jobA := enqueueOne(t, d, "ka", "transcribe", invAddr("a"), nil)
	enqueueOne(t, d, "kc", "embed", invAddr("c"), nil)
	hello(t, d, "R1", "transcribe")
	g, _ := leaseOne(t, d, "R1", "transcribe")
	if g == nil {
		t.Fatal("expected a grant")
	}
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: jobA, Attempt: 1, ActionResult: sampleResult(invAddr("a"))}); werr != nil {
		t.Fatalf("complete: %v", werr)
	}
	if werr := d.Ack(wire.Ack{JobID: jobA, Disposition: wire.DispositionPersisted}); werr != nil {
		t.Fatalf("ack: %v", werr)
	}
	clk.Set(t0 + 2*int64(statsWindowMaxS)*1000) // far beyond even the max window

	v, err := d.Stats(StatsRequest{WindowS: 100 * statsWindowMaxS})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if v.WindowS != statsWindowMaxS {
		t.Fatalf("window = %d, want the %d cap", v.WindowS, statsWindowMaxS)
	}
	// Even the capped window ends before t0 here, so nothing is counted — the
	// cap is real, not cosmetic.
	if len(v.Attempts) != 0 {
		t.Fatalf("expected no attempts inside the capped window, got %+v", v.Attempts)
	}

	// A fresh event lands inside the window again.
	if werr := d.Cancel(wire.Cancel{JobID: mustGetQueued(t, d), Reason: "test"}); werr != nil {
		t.Fatalf("cancel: %v", werr)
	}
	v, err = d.Stats(StatsRequest{WindowS: statsWindowMaxS})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if got := findAttempt(v, "embed", "cancel"); got != 1 {
		t.Fatalf("attempts[embed,cancel] = %d, want 1 (%+v)", got, v.Attempts)
	}
}

// TestStatsEmpty asserts the zero-state: no jobs, no attempts, no queue age.
func TestStatsEmpty(t *testing.T) {
	d, _ := newTestDispatcher(t)
	v, err := d.Stats(StatsRequest{})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if len(v.Jobs) != 0 || len(v.Attempts) != 0 || len(v.RecentFailures) != 0 {
		t.Fatalf("expected an empty snapshot, got %+v", v)
	}
	if v.OldestQueuedAgeS != 0 {
		t.Fatalf("oldest_queued_age_s = %d, want 0 on an empty queue", v.OldestQueuedAgeS)
	}
}

// mustGetQueued returns the single QUEUED job's id.
func mustGetQueued(t *testing.T, d *Dispatcher) string {
	t.Helper()
	res, err := d.Jobs(JobsFilter{State: "QUEUED"})
	if err != nil || len(res.Jobs) != 1 {
		t.Fatalf("queued lookup: %+v err=%v", res, err)
	}
	return res.Jobs[0].JobID
}
