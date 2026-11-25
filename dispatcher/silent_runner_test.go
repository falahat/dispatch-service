package dispatcher

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// silence is how long a runner may go unheard and still be granted work.
func silence(d *Dispatcher) int64 {
	return int64(silentAfterBeats*d.cfg.HeartbeatIntervalS) * 1000
}

// beat sends the runner's heartbeat, as the runner hello named did.
func beat(t *testing.T, d *Dispatcher, runner string) {
	t.Helper()
	if _, werr := d.Heartbeat(runner, wire.Heartbeat{Status: wire.HeartbeatStatus{Node: runner, Lanes: []string{"embed"}, Capacity: 1}}); werr != nil {
		t.Fatalf("heartbeat: %v", werr)
	}
}

// queuedUnleased fails the test unless the job is QUEUED with no lease.
func queuedUnleased(t *testing.T, d *Dispatcher, jobID, when string) {
	t.Helper()
	job, err := d.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "QUEUED" || job.LeaseID != "" {
		t.Fatalf("%s: the job is %s under lease %q; want QUEUED with no lease", when, job.State, job.LeaseID)
	}
}

// TestASilentRunnerIsGrantedNothing: a runner may vanish without closing its connections
// (its power lost, its path gone), and a relay in front of the PEP keeps them open for
// it. Its heartbeat is then the only sign it is still there: once it has missed two, it
// is granted nothing, and once it is heard again it is granted work as before.
func TestASilentRunnerIsGrantedNothing(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "R1", "embed")
	jobID := enqueueOne(t, d, "k", "embed", invAddr("silent"), nil)

	clk.Advance(silence(d) + 1)
	if g, _ := leaseOne(t, d, "R1", "embed"); g != nil {
		t.Fatalf("a runner unheard for %d ms was granted %s", silence(d)+1, g.Job.JobID)
	}
	queuedUnleased(t, d, jobID, "after a silent runner's lease")

	beat(t, d, "R1")
	if g, _ := leaseOne(t, d, "R1", "embed"); g == nil || g.Job.JobID != jobID {
		t.Fatalf("a runner heard again was not granted the job: %+v", g)
	}
}

// TestARunnerJustStartedIsGrantedWork: a runner's first heartbeat comes one interval after
// it starts, so its hello is its sign of life until then.
func TestARunnerJustStartedIsGrantedWork(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "R1", "embed")
	jobID := enqueueOne(t, d, "k", "embed", invAddr("fresh"), nil)

	clk.Advance(silence(d))
	if g, _ := leaseOne(t, d, "R1", "embed"); g == nil || g.Job.JobID != jobID {
		t.Fatalf("a runner heard from %d ms ago, by its hello, was granted nothing: %+v", silence(d), g)
	}
}

// TestASilentRunnersWaitingLeaseEndsWithoutAGrant: a runner that falls silent while its
// lease waits is granted nothing even when work arrives, and the wait ends empty at its
// deadline. It waits rather than ending at once because a runner still there asks again
// the moment it is told no.
func TestASilentRunnersWaitingLeaseEndsWithoutAGrant(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "R1", "embed")

	type answer struct {
		grant *wire.Grant
		empty *wire.Empty
		err   *wire.Error
	}
	done := make(chan answer, 1)
	began := time.Now()
	go func() {
		g, e, werr := d.Lease(context.Background(), "R1", wire.Lease{Lanes: []string{"embed"}, WaitS: d.cfg.MaxWaitS})
		done <- answer{g, e, werr}
	}()
	time.Sleep(100 * time.Millisecond) // the lease waits: nothing is queued

	clk.Advance(silence(d) + 1)
	jobID := enqueueOne(t, d, "k", "embed", invAddr("arrives"), nil)

	var got answer
	select {
	case got = <-done:
	case <-time.After(time.Duration(d.cfg.MaxWaitS)*time.Second + 2*time.Second):
		t.Fatal("the lease outlived its wait")
	}
	if got.err != nil || got.grant != nil || got.empty == nil {
		t.Fatalf("a silent runner's waiting lease answered grant %+v, empty %+v, error %v; want empty", got.grant, got.empty, got.err)
	}
	if waited := time.Since(began); waited < time.Duration(d.cfg.MaxWaitS)*time.Second-200*time.Millisecond {
		t.Fatalf("the lease ended after %v, before its %d s wait", waited, d.cfg.MaxWaitS)
	}
	queuedUnleased(t, d, jobID, "after a silent runner's waiting lease")
}

// TestTheFleetShowsASilentRunnerOffline: the fleet counts a runner online by the test
// that grants it work, so a runner granted nothing for its silence shows offline rather
// than online for the rest of a lease TTL, and online again once it is heard.
func TestTheFleetShowsASilentRunnerOffline(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "R1", "embed")
	online := func() bool {
		t.Helper()
		fleet, err := d.Fleet()
		if err != nil || len(fleet) != 1 {
			t.Fatalf("fleet: %+v, %v", fleet, err)
		}
		return fleet[0].Online
	}

	clk.Advance(silence(d))
	if !online() {
		t.Fatalf("a runner heard %d ms ago, so granted work, shows offline", silence(d))
	}
	clk.Advance(1)
	if online() {
		t.Fatalf("a runner unheard for %d ms, so granted nothing, shows online", silence(d)+1)
	}
	beat(t, d, "R1")
	if !online() {
		t.Fatal("a runner heard again shows offline")
	}
}

// TestASilentSpellIsLoggedOnce: a silent runner's waiting lease is refused again every
// pollInterval, so the dispatcher logs the first refusal of each silent spell, and the
// spell's end once the runner is heard, rather than every refusal.
func TestASilentSpellIsLoggedOnce(t *testing.T) {
	d, clk := newTestDispatcher(t)
	var said strings.Builder
	d.log = slog.New(slog.NewTextHandler(&said, nil))
	hello(t, d, "R1", "embed")

	for range 2 {
		clk.Advance(silence(d) + 1)
		for range 3 {
			leaseOne(t, d, "R1", "embed")
		}
		beat(t, d, "R1")
		leaseOne(t, d, "R1", "embed")
	}
	silent, heard := strings.Count(said.String(), "runner silent"), strings.Count(said.String(), "heard again after a silent spell")
	if silent != 2 || heard != 2 {
		t.Fatalf("two silent spells of 3 refusals each logged %d refusals and %d ends, want 2 of each:\n%s", silent, heard, said.String())
	}
}
