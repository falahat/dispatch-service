package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// silence is how long a runner may go unheard and still be granted work.
func silence(d *Dispatcher) int64 {
	return int64(silentAfterBeats*d.cfg.HeartbeatIntervalS) * 1000
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

	if _, werr := d.Heartbeat("R1", wire.Heartbeat{Status: wire.HeartbeatStatus{Node: "R1", Lanes: []string{"embed"}, Capacity: 1}}); werr != nil {
		t.Fatalf("heartbeat: %v", werr)
	}
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
