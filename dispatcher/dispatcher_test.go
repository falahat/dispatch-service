package dispatcher

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

func testConfig() Config {
	c := DefaultConfig()
	c.LeaseTTLS = 10
	c.MinWaitS = 0
	c.MaxWaitS = 2
	c.RunnerRatePerMin = 0 // disable rate limiting in most tests
	c.HeartbeatIntervalS = 1
	c.Lanes = map[string]LaneConfig{
		"transcribe": {Concurrency: 1, PersistingWatermark: 2},
		"embed":      {Concurrency: 4, PersistingWatermark: 64},
	}
	c.DefaultLane = LaneConfig{Concurrency: 0, PersistingWatermark: 8}
	return c
}

func newTestDispatcher(t *testing.T) (*Dispatcher, *ManualClock) {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	clk := NewManualClock(1_000_000)
	d, err := New(store, testConfig(), clk)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	return d, clk
}

func invAddr(s string) artifact.Address { return artifact.ComputeAddress([]byte(s)) }

func enqueueOne(t *testing.T, d *Dispatcher, key, lane string, inv artifact.Address, pol *wire.Policy) string {
	t.Helper()
	res, werr := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: key, Lane: lane, InvocationAddress: inv, Policy: pol}}})
	if werr != nil {
		t.Fatalf("enqueue: %v", werr)
	}
	if len(res.Results) != 1 {
		t.Fatalf("enqueue results = %d", len(res.Results))
	}
	return res.Results[0].JobID
}

func hello(t *testing.T, d *Dispatcher, id string, lanes ...string) {
	t.Helper()
	_, werr := d.Hello(wire.Hello{Contract: wire.ContractVersion, Runner: wire.RunnerIdent{ID: id, Version: "test", Node: id, Lanes: lanes, Capacity: 1}})
	if werr != nil {
		t.Fatalf("hello %s: %v", id, werr)
	}
}

func leaseOne(t *testing.T, d *Dispatcher, runner string, lanes ...string) (*wire.Grant, *wire.Empty) {
	t.Helper()
	g, e, werr := d.Lease(context.Background(), runner, wire.Lease{Lanes: lanes, WaitS: 0})
	if werr != nil {
		t.Fatalf("lease: %v", werr)
	}
	return g, e
}

func sampleResult(inv artifact.Address) artifact.ActionResult {
	return artifact.ActionResult{
		Kind:              artifact.ActionResultKind,
		InvocationAddress: inv,
		Outputs:           map[string]artifact.Output{"out": {Address: invAddr("out"), Size: 10}},
		Metrics:           map[string]int64{"wall_s": 1},
		Runner:            artifact.RunnerInfo{Node: "n", Version: "test"},
	}
}

func TestGrantCarriesExpectedWall(t *testing.T) {
	// A job's expected_wall_s must ride the grant so the runner can size its per-job
	// budget from it (otherwise the field is stored but inert). A job without one carries 0.
	d, _ := newTestDispatcher(t)
	wall := 300
	enqueueOne(t, d, "kw", "embed", invAddr("a"), &wire.Policy{ExpectedWallS: &wall})
	enqueueOne(t, d, "kn", "embed", invAddr("b"), nil)
	hello(t, d, "R1", "embed")

	g1, _ := leaseOne(t, d, "R1", "embed")
	g2, _ := leaseOne(t, d, "R1", "embed")
	if g1 == nil || g2 == nil {
		t.Fatal("expected two grants")
	}
	// Oldest-first: kw (the budgeted job) is granted before kn.
	if g1.Job.ExpectedWallS != 300 {
		t.Fatalf("grant expected_wall_s = %d, want 300", g1.Job.ExpectedWallS)
	}
	if g2.Job.ExpectedWallS != 0 {
		t.Fatalf("unbudgeted grant expected_wall_s = %d, want 0", g2.Job.ExpectedWallS)
	}
}

func TestClaimRoundRobinsLanesSoNeitherStarves(t *testing.T) {
	// Regression: global oldest-first froze the newer embed lane behind an OLDER transcribe
	// backlog on a shared runner (embed dead 36h, 2026-07). With lane concurrency out of the
	// way (both unlimited here), round-robin is the only thing distributing claims — two
	// consecutive claims with both lanes backlogged must hit BOTH lanes, not just the older.
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := testConfig()
	cfg.Lanes = map[string]LaneConfig{
		"transcribe": {Concurrency: 0, PersistingWatermark: 0},
		"embed":      {Concurrency: 0, PersistingWatermark: 0},
	}
	clk := NewManualClock(1_000_000)
	d, err := New(store, cfg, clk)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	enqueueOne(t, d, "t0", "transcribe", invAddr("t0"), nil)
	enqueueOne(t, d, "t1", "transcribe", invAddr("t1"), nil)
	clk.Advance(60_000) // embed is strictly NEWER — global FIFO would never reach it
	enqueueOne(t, d, "e0", "embed", invAddr("e0"), nil)
	enqueueOne(t, d, "e1", "embed", invAddr("e1"), nil)
	hello(t, d, "R1", "transcribe", "embed")

	lanes := map[string]int{}
	for i := 0; i < 2; i++ {
		g, _ := leaseOne(t, d, "R1", "transcribe", "embed")
		if g == nil {
			t.Fatalf("lease %d: no grant", i)
		}
		lanes[g.Job.Lane]++
	}
	if lanes["embed"] != 1 || lanes["transcribe"] != 1 {
		t.Fatalf("round-robin should serve both lanes in 2 claims (global FIFO starves the "+
			"newer embed lane); got %v", lanes)
	}
}

func TestEnqueueIdempotency(t *testing.T) {
	d, _ := newTestDispatcher(t)
	inv := invAddr("a")
	id1 := enqueueOne(t, d, "k1", "embed", inv, nil)

	// Same key again -> same job, created=false.
	res, _ := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: "k1", Lane: "embed", InvocationAddress: inv}}})
	if res.Results[0].JobID != id1 || res.Results[0].Created {
		t.Fatalf("expected idempotent hit, got %+v", res.Results[0])
	}

	// Duplicate key within one batch -> single creation.
	res2, _ := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "k2", Lane: "embed", InvocationAddress: inv},
		{JobKey: "k2", Lane: "embed", InvocationAddress: inv},
	}})
	if res2.Results[0].JobID != res2.Results[1].JobID {
		t.Fatalf("duplicate key in batch created two jobs")
	}

	// Terminal job frees the key.
	if werr := d.Cancel(wire.Cancel{JobID: id1, Reason: "test"}); werr != nil {
		t.Fatalf("cancel: %v", werr)
	}
	res3, _ := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: "k1", Lane: "embed", InvocationAddress: inv}}})
	if !res3.Results[0].Created || res3.Results[0].JobID == id1 {
		t.Fatalf("terminal key not reusable: %+v", res3.Results[0])
	}
}

func TestClaimAndComplete(t *testing.T) {
	d, _ := newTestDispatcher(t)
	inv := invAddr("job1")
	id := enqueueOne(t, d, "k", "transcribe", inv, nil)
	hello(t, d, "R1", "transcribe")

	g, e := leaseOne(t, d, "R1", "transcribe")
	if g == nil {
		t.Fatalf("expected grant, got empty %+v", e)
	}
	if g.Job.JobID != id || g.Job.Attempt != 1 || g.Job.InvocationAddress != inv {
		t.Fatalf("bad grant: %+v", g.Job)
	}

	// Lane at capacity now: a second lease finds no work.
	if g2, _ := leaseOne(t, d, "R1", "transcribe"); g2 != nil {
		t.Fatalf("expected no second grant (lane cap=1)")
	}

	// Wrong lease_id is fenced.
	if werr := d.Complete("R1", wire.Complete{LeaseID: "l_0000000000000000000000000Z", JobID: id, Attempt: 1, ActionResult: sampleResult(inv)}); werr == nil || werr.Code != wire.CodeNotLeaseholder {
		t.Fatalf("expected not_leaseholder, got %v", werr)
	}
	job, _ := d.GetJob(id)
	if job.State != "RUNNING" {
		t.Fatalf("state changed under a fenced complete: %s", job.State)
	}

	// Live leaseholder completes -> PERSISTING.
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: sampleResult(inv)}); werr != nil {
		t.Fatalf("complete: %v", werr)
	}
	job, _ = d.GetJob(id)
	if job.State != "PERSISTING" {
		t.Fatalf("state = %s, want PERSISTING", job.State)
	}

	// Exact replay -> ok; divergent replay -> conflict.
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: sampleResult(inv)}); werr != nil {
		t.Fatalf("idempotent replay should be ok: %v", werr)
	}
	diverge := sampleResult(inv)
	diverge.Metrics["wall_s"] = 999
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: diverge}); werr == nil || werr.Code != wire.CodeConflict {
		t.Fatalf("divergent replay should conflict, got %v", werr)
	}
}

func TestCompleteRejectsMismatchedInvocation(t *testing.T) {
	d, _ := newTestDispatcher(t)
	inv := invAddr("real")
	id := enqueueOne(t, d, "k", "embed", inv, nil)
	hello(t, d, "R1", "embed")
	g, _ := leaseOne(t, d, "R1", "embed")
	// action_result echoes a DIFFERENT invocation_address than the grant.
	bad := sampleResult(invAddr("forged"))
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: bad}); werr == nil || werr.Code != wire.CodeInvalid {
		t.Fatalf("expected invalid for mismatched invocation_address, got %v", werr)
	}
}

func TestFailRetriableThenTerminal(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	maxAtt := 3
	id := enqueueOne(t, d, "k", "embed", inv, &wire.Policy{MaxAttempts: &maxAtt})
	hello(t, d, "R1", "embed")

	g, _ := leaseOne(t, d, "R1", "embed")
	if werr := d.Fail("R1", wire.Fail{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ErrorClass: wire.ClassOOM, Message: "oom"}); werr != nil {
		t.Fatalf("fail: %v", werr)
	}
	job, _ := d.GetJob(id)
	if job.State != "QUEUED" || job.Attempt != 2 || job.BatchScale != "0.5" {
		t.Fatalf("after oom fail: state=%s attempt=%d batch=%s", job.State, job.Attempt, job.BatchScale)
	}
	if job.NextAttemptAt <= clk.NowMS() {
		t.Fatalf("expected backoff into the future")
	}

	// Advance past backoff; re-claim carries the halved hint.
	clk.Set(job.NextAttemptAt + 1)
	g2, _ := leaseOne(t, d, "R1", "embed")
	if g2 == nil || g2.Job.Attempt != 2 || g2.Job.Hints == nil || g2.Job.Hints.BatchScale != "0.5" {
		t.Fatalf("re-claim missing oom hint: %+v", g2)
	}

	// A terminal class fails immediately.
	if werr := d.Fail("R1", wire.Fail{LeaseID: g2.Lease.LeaseID, JobID: id, Attempt: 2, ErrorClass: wire.ClassBadInput, Message: "bad"}); werr != nil {
		t.Fatalf("fail2: %v", werr)
	}
	job, _ = d.GetJob(id)
	if job.State != "FAILED" {
		t.Fatalf("terminal class should fail, state=%s", job.State)
	}
}

func TestFailExhaustsAttempts(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	maxAtt := 2
	id := enqueueOne(t, d, "k", "embed", inv, &wire.Policy{MaxAttempts: &maxAtt})
	hello(t, d, "R1", "embed")

	for att := 1; att <= 2; att++ {
		g, e := leaseOne(t, d, "R1", "embed")
		if g == nil {
			t.Fatalf("attempt %d: no grant (%+v)", att, e)
		}
		werr := d.Fail("R1", wire.Fail{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: att, ErrorClass: wire.ClassTimeout, Message: "t"})
		if werr != nil {
			t.Fatalf("fail: %v", werr)
		}
		job, _ := d.GetJob(id)
		if att == 1 {
			if job.State != "QUEUED" {
				t.Fatalf("attempt1 should requeue, got %s", job.State)
			}
			clk.Set(job.NextAttemptAt + 1)
		} else if job.State != "FAILED" {
			t.Fatalf("attempt2 should exhaust to FAILED, got %s", job.State)
		}
	}
}

// A release reason that is a VERDICT about this job on this runner still
// dead-letters at the configured (small) cap, now carrying its reason forward.
func TestReleaseCapTerminalReason(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	cap := 3
	id := enqueueOne(t, d, "k", "embed", inv, &wire.Policy{ReleaseCap: &cap})
	hello(t, d, "R1", "embed")
	for i := 0; i < 3; i++ {
		g, e := leaseOne(t, d, "R1", "embed")
		if g == nil {
			t.Fatalf("release round %d: no grant (%+v)", i, e)
		}
		if werr := d.Release("R1", wire.Release{LeaseID: g.Lease.LeaseID, JobID: id, Reason: wire.ReleaseWrongHardware}); werr != nil {
			t.Fatalf("release: %v", werr)
		}
		job, _ := d.GetJob(id)
		if i < 2 {
			if job.State != "QUEUED" || job.Attempt != 1 {
				t.Fatalf("release should requeue with attempt unchanged: state=%s attempt=%d", job.State, job.Attempt)
			}
			clk.Set(job.NextAttemptAt + 1)
		} else if job.State != "FAILED" || job.Reason != "unstartable:wrong_hardware" {
			t.Fatalf("terminal release should FAIL naming the reason: state=%s reason=%s", job.State, job.Reason)
		}
	}
}

// THE regression: during the 2026-07 brownout the auth plane briefly denied CAS
// reads, and because every release shared one tiny cap the 1s..32s pacing exhausted
// it in well under a minute — permanently failing healthy jobs over a self-clearing
// outage.
func TestTransientReleaseDoesNotBurnThePoisonBudget(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	cap := 3
	id := enqueueOne(t, d, "k", "embed", inv, &wire.Policy{ReleaseCap: &cap})
	hello(t, d, "R1", "embed")
	for i := 0; i < 6; i++ { // twice the terminal cap
		g, e := leaseOne(t, d, "R1", "embed")
		if g == nil {
			t.Fatalf("release round %d: no grant (%+v)", i, e)
		}
		if werr := d.Release("R1", wire.Release{LeaseID: g.Lease.LeaseID, JobID: id, Reason: wire.ReleaseCASUnreachable}); werr != nil {
			t.Fatalf("release: %v", werr)
		}
		job, _ := d.GetJob(id)
		if job.State != "QUEUED" {
			t.Fatalf("round %d: a transient CAS outage must not dead-letter a healthy job: state=%s reason=%s",
				i, job.State, job.Reason)
		}
		clk.Set(job.NextAttemptAt + 1)
	}
}

// Transient must not mean unbounded: a runner releasing forever has to fail closed
// to a visible terminal state rather than spin silently.
func TestTransientReleaseStillTerminates(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	id := enqueueOne(t, d, "k", "embed", inv, nil)
	hello(t, d, "R1", "embed")
	for i := 0; i < transientReleaseCap+1; i++ {
		g, _ := leaseOne(t, d, "R1", "embed")
		if g == nil {
			break // already dead-lettered
		}
		if werr := d.Release("R1", wire.Release{LeaseID: g.Lease.LeaseID, JobID: id, Reason: wire.ReleaseShipping}); werr != nil {
			t.Fatalf("release: %v", werr)
		}
		job, _ := d.GetJob(id)
		clk.Set(job.NextAttemptAt + 1)
	}
	job, _ := d.GetJob(id)
	if job.State != "FAILED" {
		t.Fatalf("a release loop must terminate visibly, got state=%s", job.State)
	}
}

// An evicted content-addressed input is not a dead end — the app still holds the
// source bytes — so the reason must say so instead of collapsing to 'unstartable',
// which erased the app's ability to re-stage and retry.
func TestCASMissDeadLettersAsRecoverable(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	cap := 2
	id := enqueueOne(t, d, "k", "embed", inv, &wire.Policy{ReleaseCap: &cap})
	hello(t, d, "R1", "embed")
	for i := 0; i < 2; i++ {
		g, _ := leaseOne(t, d, "R1", "embed")
		if g == nil {
			t.Fatalf("round %d: no grant", i)
		}
		if werr := d.Release("R1", wire.Release{LeaseID: g.Lease.LeaseID, JobID: id, Reason: wire.ReleaseCASMiss}); werr != nil {
			t.Fatalf("release: %v", werr)
		}
		job, _ := d.GetJob(id)
		clk.Set(job.NextAttemptAt + 1)
	}
	job, _ := d.GetJob(id)
	if job.State != "FAILED" || job.Reason != "input_evicted" {
		t.Fatalf("cas_miss should dead-letter as input_evicted: state=%s reason=%s", job.State, job.Reason)
	}
}

func TestSweepRecoversExpiredLease(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	id := enqueueOne(t, d, "k", "embed", inv, nil)
	hello(t, d, "R1", "embed")
	g, _ := leaseOne(t, d, "R1", "embed")

	// Advance past the lease deadline; sweep presumes a crash and requeues.
	clk.Set(g.Lease.DeadlineTS + 1)
	res, err := d.Sweep()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Recovered != 1 {
		t.Fatalf("recovered = %d, want 1", res.Recovered)
	}
	job, _ := d.GetJob(id)
	if job.State != "QUEUED" || job.Attempt != 2 {
		t.Fatalf("after sweep: state=%s attempt=%d (want QUEUED/2)", job.State, job.Attempt)
	}
	// The old lease is dead: a late complete is fenced.
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: sampleResult(inv)}); werr == nil || werr.Code != wire.CodeNotLeaseholder {
		t.Fatalf("late complete on expired lease should be fenced, got %v", werr)
	}
}

func TestAckAndInbox(t *testing.T) {
	d, _ := newTestDispatcher(t)
	inv := invAddr("j")
	id := enqueueOne(t, d, "k", "embed", inv, nil)
	hello(t, d, "R1", "embed")
	g, _ := leaseOne(t, d, "R1", "embed")
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: sampleResult(inv)}); werr != nil {
		t.Fatalf("complete: %v", werr)
	}

	batch, err := d.persistingBatch(nil)
	if err != nil || len(batch) != 1 || batch[0].JobID != id {
		t.Fatalf("inbox = %+v err=%v", batch, err)
	}

	if werr := d.Ack(wire.Ack{JobID: id, Disposition: wire.DispositionPersisted}); werr != nil {
		t.Fatalf("ack: %v", werr)
	}
	job, _ := d.GetJob(id)
	if job.State != "SUCCEEDED" {
		t.Fatalf("state=%s want SUCCEEDED", job.State)
	}
	batch, _ = d.persistingBatch(nil)
	if len(batch) != 0 {
		t.Fatalf("inbox not drained after ack: %+v", batch)
	}
	// Ack is idempotent.
	if werr := d.Ack(wire.Ack{JobID: id, Disposition: wire.DispositionPersisted}); werr != nil {
		t.Fatalf("ack replay should be ok: %v", werr)
	}
}

func TestBackpressurePausesLane(t *testing.T) {
	d, _ := newTestDispatcher(t)
	// transcribe watermark=2. Push 3 jobs to PERSISTING; but lane cap=1 means
	// serialize. Use embed-like unbounded concurrency by putting them on a lane
	// with high concurrency but low watermark.
	c := d.cfg
	c.Lanes["bp"] = LaneConfig{Concurrency: 10, PersistingWatermark: 2}
	d.cfg = c
	inv := invAddr("j")
	hello(t, d, "R1", "bp")
	var jobs []string
	for i := 0; i < 3; i++ {
		jobs = append(jobs, enqueueOne(t, d, "k"+string(rune('a'+i)), "bp", invAddr(string(rune('a'+i))), nil))
	}
	// Claim + complete all 3 into PERSISTING.
	for range jobs {
		g, e := leaseOne(t, d, "R1", "bp")
		if g == nil {
			t.Fatalf("expected grant, got %+v", e)
		}
		if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: g.Job.JobID, Attempt: 1, ActionResult: sampleResult(artifact.Address(g.Job.InvocationAddress))}); werr != nil {
			t.Fatalf("complete: %v", werr)
		}
	}
	_ = inv
	// Now PERSISTING count (3) > watermark (2): enqueue a new one and lease.
	enqueueOne(t, d, "knew", "bp", invAddr("new"), nil)
	g, e := leaseOne(t, d, "R1", "bp")
	if g != nil || e == nil || e.Reason != "backpressure" {
		t.Fatalf("expected backpressure empty, got grant=%v empty=%+v", g, e)
	}
}

func TestTwoWitnessQuarantine(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "A", "embed")
	hello(t, d, "B", "embed")
	maxAtt := 3

	runOne := func(key string) {
		inv := invAddr(key)
		id := enqueueOne(t, d, key, "embed", inv, &wire.Policy{MaxAttempts: &maxAtt})
		// A claims and fails.
		gA, _ := leaseOne(t, d, "A", "embed")
		if gA == nil || gA.Job.JobID != id {
			t.Fatalf("A did not claim %s", key)
		}
		if werr := d.Fail("A", wire.Fail{LeaseID: gA.Lease.LeaseID, JobID: id, Attempt: 1, ErrorClass: wire.ClassOOM, Message: "x"}); werr != nil {
			t.Fatalf("A fail: %v", werr)
		}
		job, _ := d.GetJob(id)
		clk.Set(job.NextAttemptAt + 1)
		// B claims and completes; app acks -> success on a different runner.
		gB, _ := leaseOne(t, d, "B", "embed")
		if gB == nil || gB.Job.JobID != id {
			t.Fatalf("B did not claim %s", key)
		}
		if werr := d.Complete("B", wire.Complete{LeaseID: gB.Lease.LeaseID, JobID: id, Attempt: 2, ActionResult: sampleResult(inv)}); werr != nil {
			t.Fatalf("B complete: %v", werr)
		}
		if werr := d.Ack(wire.Ack{JobID: id, Disposition: wire.DispositionPersisted}); werr != nil {
			t.Fatalf("ack: %v", werr)
		}
	}
	runOne("job-1") // A: 1 corroborated failure
	fleet, _ := d.Fleet()
	if quarantinedOf(fleet, "A") {
		t.Fatalf("A quarantined after a single corroborated failure")
	}
	runOne("job-2") // A: 2 corroborated failures -> quarantine
	fleet, _ = d.Fleet()
	if !quarantinedOf(fleet, "A") {
		t.Fatalf("A not quarantined after two corroborated failures")
	}

	// A quarantined -> its lease gets empty even with work available.
	enqueueOne(t, d, "job-3", "embed", invAddr("job-3"), nil)
	if g, e := leaseOne(t, d, "A", "embed"); g != nil {
		t.Fatalf("quarantined runner got a grant: %+v (empty %+v)", g, e)
	}
	// B is healthy and can still claim.
	if g, _ := leaseOne(t, d, "B", "embed"); g == nil {
		t.Fatalf("healthy runner B could not claim")
	}
}

func quarantinedOf(fleet []RunnerView, id string) bool {
	for _, r := range fleet {
		if r.RunnerID == id {
			return r.Quarantined
		}
	}
	return false
}

func TestCostGate(t *testing.T) {
	d, _ := newTestDispatcher(t)
	inv := invAddr("priced")
	// Cap is $0 by default -> priced job is rejected.
	_, werr := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: "p", Lane: "embed", InvocationAddress: inv, CostEstimateUSD: "1.50"}}})
	if werr == nil || werr.Code != wire.CodeBudget {
		t.Fatalf("expected budget rejection at $0 cap, got %v", werr)
	}

	// Raise the cap; the job parks in AWAITING_APPROVAL.
	if err := d.store.SetBudgetCap("10.00"); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	res, werr := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: "p", Lane: "embed", InvocationAddress: inv, CostEstimateUSD: "1.50"}}})
	if werr != nil {
		t.Fatalf("priced enqueue: %v", werr)
	}
	id := res.Results[0].JobID
	job, _ := d.GetJob(id)
	if job.State != "AWAITING_APPROVAL" {
		t.Fatalf("priced job state=%s want AWAITING_APPROVAL", job.State)
	}
	b, _ := d.Budget()
	if b.ReservedUSD != "1.50" {
		t.Fatalf("reserved=%s want 1.50", b.ReservedUSD)
	}

	// Approve -> QUEUED; reservation still held.
	if werr := d.Approve(wire.Approval{JobID: id, Author: "aryan", Reason: "ok"}); werr != nil {
		t.Fatalf("approve: %v", werr)
	}
	job, _ = d.GetJob(id)
	if job.State != "QUEUED" {
		t.Fatalf("after approve state=%s want QUEUED", job.State)
	}
}

func TestCancelRunningAbandons(t *testing.T) {
	d, _ := newTestDispatcher(t)
	inv := invAddr("j")
	id := enqueueOne(t, d, "k", "embed", inv, nil)
	hello(t, d, "R1", "embed")
	g, _ := leaseOne(t, d, "R1", "embed")

	if werr := d.Cancel(wire.Cancel{JobID: id, Reason: "user"}); werr != nil {
		t.Fatalf("cancel: %v", werr)
	}
	job, _ := d.GetJob(id)
	if job.State != "CANCELLED" {
		t.Fatalf("state=%s want CANCELLED", job.State)
	}
	// Heartbeat with the now-void lease -> abandon directive.
	beat, werr := d.Heartbeat("R1", wire.Heartbeat{Status: wire.HeartbeatStatus{Node: "R1", Lanes: []string{"embed"}, Capacity: 1, CurrentJobID: id}, LeaseID: g.Lease.LeaseID})
	if werr != nil {
		t.Fatalf("heartbeat: %v", werr)
	}
	found := false
	for _, dir := range beat.Directives {
		if dir.Kind == wire.DirectiveAbandon && dir.JobID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected abandon directive, got %+v", beat.Directives)
	}
	// A late complete on the void lease is fenced.
	if werr := d.Complete("R1", wire.Complete{LeaseID: g.Lease.LeaseID, JobID: id, Attempt: 1, ActionResult: sampleResult(inv)}); werr == nil {
		t.Fatalf("complete after cancel should be rejected")
	}
}

func TestHeartbeatRenewsLease(t *testing.T) {
	d, clk := newTestDispatcher(t)
	inv := invAddr("j")
	id := enqueueOne(t, d, "k", "embed", inv, nil)
	hello(t, d, "R1", "embed")
	g, _ := leaseOne(t, d, "R1", "embed")
	orig := g.Lease.DeadlineTS

	clk.Advance(3000)
	if _, werr := d.Heartbeat("R1", wire.Heartbeat{Status: wire.HeartbeatStatus{Node: "R1", Lanes: []string{"embed"}, Capacity: 1, CurrentJobID: id}, LeaseID: g.Lease.LeaseID}); werr != nil {
		t.Fatalf("heartbeat: %v", werr)
	}
	job, _ := d.GetJob(id)
	if job.LeaseDeadlineTS <= orig {
		t.Fatalf("lease not renewed: %d <= %d", job.LeaseDeadlineTS, orig)
	}
}
