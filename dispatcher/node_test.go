package dispatcher

import (
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func pinned(node string) *wire.Policy { return &wire.Policy{Node: &node} }

func TestPinnedJobGoesOnlyToItsNode(t *testing.T) {
	d, _ := newTestDispatcher(t)
	helloOn(t, d, "laptop-1", "laptop", "pose")
	helloOn(t, d, "bigboi-1", "bigboi", "pose")
	there := enqueueOne(t, d, "there", "pose", invAddr("there"), pinned("bigboi"))
	anywhere := enqueueOne(t, d, "anywhere", "pose", invAddr("anywhere"), nil)

	if g, _ := leaseOne(t, d, "laptop-1", "pose"); g == nil || g.Job.JobID != anywhere {
		t.Fatalf("the laptop must skip the older job pinned to bigboi and take the free one: %+v", g)
	}
	if g, _ := leaseOne(t, d, "laptop-1", "pose"); g != nil {
		t.Fatalf("the laptop took a job pinned to bigboi: %+v", g)
	}
	if g, _ := leaseOne(t, d, "bigboi-1", "pose"); g == nil || g.Job.JobID != there {
		t.Fatalf("bigboi did not get its pinned job: %+v", g)
	}
}

func TestPinnedJobWaitsForARunnerOfItsNode(t *testing.T) {
	d, _ := newTestDispatcher(t)
	helloOn(t, d, "laptop-1", "laptop", "pose")
	job := enqueueOne(t, d, "vm-run", "pose", invAddr("vm-run"), pinned("pose-l4"))
	if g, _ := leaseOne(t, d, "laptop-1", "pose"); g != nil {
		t.Fatalf("a runner of another node took the job: %+v", g)
	}
	helloOn(t, d, "vm-1", "pose-l4", "pose")
	if g, _ := leaseOne(t, d, "vm-1", "pose"); g == nil || g.Job.JobID != job {
		t.Fatalf("the node's runner did not get the job once it connected: %+v", g)
	}
}

func TestEnqueueRefusesAnInvalidNode(t *testing.T) {
	d, _ := newTestDispatcher(t)
	for _, node := range []string{"", "a/b", "-lead", "has space", "n\x00", string(make([]byte, 65))} {
		_, werr := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: "k", Lane: "pose", InvocationAddress: invAddr("k"), Policy: pinned(node)}}})
		if werr == nil || werr.Code != wire.CodeInvalid {
			t.Errorf("node %q: %v", node, werr)
		}
	}
}

// A starved GPU job pinned to one node holds back only that node's GPUs: a
// runner elsewhere keeps starting its own work.
func TestStarvedPinnedJobHoldsBackOnlyItsNode(t *testing.T) {
	d, clk := newTestDispatcher(t)
	helloOn(t, d, "bigboi-1", "bigboi", "pose")
	helloOn(t, d, "laptop-1", "laptop", "pose")
	need := wire.GPUNeed{MemoryMB: 7000}
	node := "bigboi"
	enqueueOne(t, d, "big", "pose", invAddr("big"), &wire.Policy{GPU: &need, Node: &node})
	clk.Advance(int64(d.cfg.GPUStarveAfterS) * 1000)
	gpuJob(t, d, "small", "pose", 1000, "")

	busy := []wire.GPUReading{reading(gpuA, 0, 8192, 2000, 1)}
	if g := leaseGPUs(t, d, "bigboi-1", busy, "pose"); g != nil {
		t.Fatalf("bigboi started other work past its starved job: %+v", g)
	}
	if g := leaseGPUs(t, d, "laptop-1", []wire.GPUReading{reading(gpuB, 0, 8192, 8000, 0)}, "pose"); g == nil || g.Job.JobKey != "small" {
		t.Fatalf("the laptop was held back by a job it can never run: %+v", g)
	}
}

// A dispatcher that was down longer than the lease TTL gives running leases a
// full TTL when it starts, so their runners can report in; a runner that never
// does still loses its lease one TTL later.
func TestRestartRenewsRunningLeases(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	job := enqueueOne(t, d, "long", "embed", invAddr("long"), nil)
	g, _ := leaseOne(t, d, "r1", "embed")
	if g == nil {
		t.Fatal("no grant")
	}
	clk.Advance(int64(d.cfg.LeaseTTLS)*1000*3 + 1)

	restarted, err := New(d.store, d.cfg, clk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Sweep(); err != nil {
		t.Fatal(err)
	}
	if view, _ := restarted.GetJob(job); view.State != "RUNNING" || view.LeaseID != g.Lease.LeaseID {
		t.Fatalf("the restart let a live lease lapse: %+v", view)
	}
	if _, werr := restarted.Heartbeat("r1", wire.Heartbeat{Status: wire.HeartbeatStatus{Node: "r1", Lanes: []string{"embed"}, Capacity: 1, CurrentJobID: job}, LeaseID: g.Lease.LeaseID}); werr != nil {
		t.Fatal(werr)
	}
	clk.Advance(int64(d.cfg.LeaseTTLS)*1000 - 1)
	if _, err := restarted.Sweep(); err != nil {
		t.Fatal(err)
	}
	if view, _ := restarted.GetJob(job); view.State != "RUNNING" {
		t.Fatalf("a renewed lease expired early: %+v", view)
	}
	clk.Advance(2)
	if _, err := restarted.Sweep(); err != nil {
		t.Fatal(err)
	}
	if view, _ := restarted.GetJob(job); view.State == "RUNNING" {
		t.Fatalf("a lease nobody renewed outlived its TTL: %+v", view)
	}
}
