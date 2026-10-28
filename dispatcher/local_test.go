package dispatcher

import (
	"context"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func TestSingleAttemptIncludesInfrastructureAndLeaseLoss(t *testing.T) {
	for _, outcome := range []string{"fail", "release", "lease_loss"} {
		t.Run(outcome, func(t *testing.T) {
			d, clock := newTestDispatcher(t)
			d.cfg.Lanes["build"] = LaneConfig{SingleAttempt: true}
			many := 10
			id := enqueueOne(t, d, outcome, "build", invAddr(outcome), &wire.Policy{MaxAttempts: &many})
			hello(t, d, "worker", "build")
			grant, _ := leaseOne(t, d, "worker", "build")
			switch outcome {
			case "fail":
				if err := d.Fail("worker", wire.Fail{JobID: id, LeaseID: grant.Lease.LeaseID, Attempt: 1, ErrorClass: wire.ClassNetwork}); err != nil {
					t.Fatal(err)
				}
			case "release":
				if err := d.Release("worker", wire.Release{JobID: id, LeaseID: grant.Lease.LeaseID, Reason: wire.ReleaseCASUnreachable}); err != nil {
					t.Fatal(err)
				}
			case "lease_loss":
				clock.Advance(11000)
				if _, err := d.Sweep(); err != nil {
					t.Fatal(err)
				}
			}
			job, err := d.GetJob(id)
			if err != nil || job.State != "FAILED" || job.Attempt != 1 {
				t.Fatalf("single execution must fail visibly: %+v %v", job, err)
			}
		})
	}
}

func TestIndependentWaitersAndCancellationSettlement(t *testing.T) {
	d, _ := newTestDispatcher(t)
	d.cfg.WaitForExecutor = true
	id := enqueueOne(t, d, "wait", "embed", invAddr("wait"), nil)
	hello(t, d, "worker", "embed")
	leaseOne(t, d, "worker", "embed")
	if err := d.Cancel(wire.Cancel{JobID: id}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.job(ctx, id, true); err == nil {
		t.Fatal("cancellation returned before the executor settled")
	}
	results := make(chan map[string]any, 2)
	for range 2 {
		go func() {
			result, err := d.job(context.Background(), id, true)
			if err != nil {
				t.Error(err)
			}
			results <- result
		}()
	}
	if err := d.ExecutionSettled(id); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if result := <-results; result["state"] != "CANCELLED" {
			t.Fatalf("both clients must observe cancellation: %v", result)
		}
	}
}
