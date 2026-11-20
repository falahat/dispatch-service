package dispatcher

import (
	"context"
	"strings"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func helloOn(t *testing.T, d *Dispatcher, id, node string, lanes ...string) {
	t.Helper()
	if _, werr := d.Hello(wire.Hello{Contract: wire.ContractVersion, Runner: wire.RunnerIdent{ID: id, Version: "test", Node: node, Lanes: lanes, Capacity: 1}}); werr != nil {
		t.Fatalf("hello %s: %v", id, werr)
	}
}

func TestHoldStopsTheNodeTakingWorkUntilUnhold(t *testing.T) {
	d, _ := newTestDispatcher(t)
	helloOn(t, d, "laptop-1", "laptop", "embed")
	helloOn(t, d, "laptop-2", "laptop", "embed")
	helloOn(t, d, "bigboi-1", "bigboi", "embed")
	running := enqueueOne(t, d, "running", "embed", invAddr("running"), nil)
	grant, _ := leaseOne(t, d, "laptop-1", "embed")
	if grant == nil || grant.Job.JobID != running {
		t.Fatalf("first grant: %+v", grant)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.hold(ctx, "laptop", "wsl restart", true); err == nil || err.Code != wire.CodeGone {
		t.Fatalf("hold with work running returned before it settled: %v", err)
	}
	if view, _ := d.GetJob(running); view.State != "RUNNING" || view.CancelRequested {
		t.Fatalf("hold altered the running job: %+v", view)
	}
	queued := enqueueOne(t, d, "queued", "embed", invAddr("queued"), nil)
	if next, empty := leaseOne(t, d, "laptop-2", "embed"); next != nil || empty == nil || empty.Reason != "" {
		t.Fatalf("a held node took work: %+v %+v", next, empty)
	}
	fleet, _ := d.Fleet()
	for _, runner := range fleet {
		if runner.Held != (runner.Node == "laptop") {
			t.Fatalf("fleet hold marks: %+v", fleet)
		}
	}
	if holds, _ := d.Holds(); len(holds) != 1 || holds[0].Node != "laptop" || holds[0].Reason != "wsl restart" || holds[0].SinceTS == 0 {
		t.Fatalf("holds: %+v", holds)
	}
	if err := d.Complete("laptop-1", wire.Complete{LeaseID: grant.Lease.LeaseID, JobID: running, Attempt: 1, ActionResult: sampleResult(invAddr("running"))}); err != nil {
		t.Fatal(err)
	}
	if err := d.hold(context.Background(), "laptop", "wsl restart", true); err != nil {
		t.Fatalf("hold of a node with nothing running: %v", err)
	}
	if err := d.hold(context.Background(), "laptop", "", false); err != nil {
		t.Fatal(err)
	}
	if next, _ := leaseOne(t, d, "laptop-2", "embed"); next == nil || next.Job.JobID != queued {
		t.Fatalf("unheld node got no work: %+v", next)
	}
	if holds, _ := d.Holds(); len(holds) != 0 {
		t.Fatalf("holds after unhold: %+v", holds)
	}
}

func TestHoldCoversRunnersThatConnectLater(t *testing.T) {
	d, _ := newTestDispatcher(t)
	if err := d.hold(context.Background(), "vm", "demo", true); err != nil {
		t.Fatal(err)
	}
	enqueueOne(t, d, "waiting", "embed", invAddr("waiting"), nil)
	helloOn(t, d, "vm-1", "vm", "embed")
	if next, _ := leaseOne(t, d, "vm-1", "embed"); next != nil {
		t.Fatalf("runner of a held node took work: %+v", next)
	}
	if err := d.hold(context.Background(), "vm", "", false); err != nil {
		t.Fatal(err)
	}
	if next, _ := leaseOne(t, d, "vm-1", "embed"); next == nil {
		t.Fatal("unheld runner got no work")
	}
}

func TestHoldRejectsInvalidNodeOrReason(t *testing.T) {
	d, _ := newTestDispatcher(t)
	for _, c := range []struct{ node, reason string }{{"", ""}, {strings.Repeat("n", 129), ""}, {"vm", strings.Repeat("r", 1025)}} {
		if err := d.hold(context.Background(), c.node, c.reason, true); err == nil || err.Code != wire.CodeInvalid {
			t.Fatalf("accepted node %d bytes, reason %d bytes: %v", len(c.node), len(c.reason), err)
		}
	}
}
