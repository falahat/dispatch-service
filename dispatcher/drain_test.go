package dispatcher

import (
	"context"
	"strings"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func TestDrainClosesAdmissionWithoutCancellingWork(t *testing.T) {
	d, clock := newTestDispatcher(t)
	hello(t, d, "worker", "embed")
	job := enqueueOne(t, d, "active", "embed", invAddr("first"), nil)
	grant, _ := leaseOne(t, d, "worker", "embed")
	if grant == nil {
		t.Fatal("missing first grant")
	}
	enqueueOne(t, d, "pending", "embed", invAddr("second"), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.drain(ctx, "worker", true); err == nil || err.Code != wire.CodeGone {
		t.Fatalf("interrupted wait: %v", err)
	}
	view, _ := d.GetJob(job)
	if view.State != "RUNNING" || view.CancelRequested {
		t.Fatalf("drain altered current job: %+v", view)
	}
	if next, empty := leaseOne(t, d, "worker", "embed"); next != nil || empty.Reason != "drained" {
		t.Fatalf("draining worker admitted work: %+v %+v", next, empty)
	}
	if err := d.Complete("worker", wire.Complete{LeaseID: grant.Lease.LeaseID, JobID: job, Attempt: 1, ActionResult: sampleResult(invAddr("first"))}); err != nil {
		t.Fatal(err)
	}
	if err := d.drain(context.Background(), "worker", true); err != nil {
		t.Fatal(err)
	}
	if err := d.drain(context.Background(), "worker", false); err != nil {
		t.Fatal(err)
	}
	if next, _ := leaseOne(t, d, "worker", "embed"); next == nil {
		t.Fatal("resumed worker cannot lease")
	}
	fleet, _ := d.Fleet()
	if !fleet[0].Online {
		t.Fatal("new heartbeat is offline")
	}
	clock.Advance(10_000)
	fleet, _ = d.Fleet()
	if fleet[0].Online {
		t.Fatal("expired heartbeat is online")
	}
}

func TestDrainRejectsUnknownAndInvalidRunner(t *testing.T) {
	d, _ := newTestDispatcher(t)
	for _, id := range []string{"", strings.Repeat("x", 129), "missing"} {
		if err := d.drain(context.Background(), id, true); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}
