package dispatcher

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func TestProgressVisibleDuringExecution(t *testing.T) {
	d, _ := newTestDispatcher(t)
	id := enqueueOne(t, d, "progress", "embed", invAddr("progress"), nil)
	hello(t, d, "worker", "embed")
	grant, _ := leaseOne(t, d, "worker", "embed")
	for _, payload := range []string{`{"stage":"first"}`, `{"stage":"second","completed":1}`} {
		_, err := d.Heartbeat("worker", wire.Heartbeat{
			Status:  wire.HeartbeatStatus{Node: "worker", Lanes: []string{"embed"}, Capacity: 1, CurrentJobID: id},
			LeaseID: grant.Lease.LeaseID, Progress: json.RawMessage(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := d.job(context.Background(), id, false)
		if err != nil || result.State != "RUNNING" || string(result.Progress) != payload {
			t.Fatalf("progress must be visible before completion: %v %v", result, err)
		}
	}
}

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
	grant, _ := leaseOne(t, d, "worker", "embed")
	if err := d.Cancel(wire.Cancel{JobID: id}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.job(ctx, id, true); err == nil {
		t.Fatal("cancellation returned before the executor settled")
	}
	results := make(chan wire.JobView, 2)
	for range 2 {
		go func() {
			result, err := d.job(context.Background(), id, true)
			if err != nil {
				t.Error(err)
			}
			results <- result
		}()
	}
	if err := d.Complete("worker", wire.Complete{JobID: id, LeaseID: grant.Lease.LeaseID, Attempt: 1, ActionResult: sampleResult(invAddr("wait"))}); err != nil {
		t.Fatal(err)
	}
	if err := d.Ack(wire.Ack{JobID: id, Disposition: wire.DispositionPersisted}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if result := <-results; result.State != "CANCELLED" {
			t.Fatalf("both clients must observe cancellation: %v", result)
		}
	}
}

func TestIdleClaimDoesNotWakeItself(t *testing.T) {
	d, _ := newTestDispatcher(t)
	hello(t, d, "worker", "embed")
	wake := d.leaseWake.wait()
	result, err := d.tryClaim("worker", []string{"embed"})
	if err != nil || result.outcome != claimNoWork {
		t.Fatalf("idle claim: %v %v", result, err)
	}
	select {
	case <-wake:
		t.Fatal("an empty claim woke its own long-poll and would busy-loop")
	default:
	}
}

func TestLostQueueStateAbandonsPreviouslyGrantedWork(t *testing.T) {
	before, _ := newTestDispatcher(t)
	id := enqueueOne(t, before, "lost-state", "embed", invAddr("lost-state"), nil)
	hello(t, before, "worker", "embed")
	grant, _ := leaseOne(t, before, "worker", "embed")
	after, _ := newTestDispatcher(t)
	hello(t, after, "worker", "embed")
	beat, err := after.Heartbeat("worker", wire.Heartbeat{
		Status:  wire.HeartbeatStatus{Node: "worker", Lanes: []string{"embed"}, Capacity: 1, CurrentJobID: id},
		LeaseID: grant.Lease.LeaseID,
	})
	if err != nil || len(beat.Directives) != 1 || beat.Directives[0].Kind != wire.DirectiveAbandon || beat.Directives[0].JobID != id {
		t.Fatalf("lost lease must stop the previously granted executor: %+v %v", beat, err)
	}
}
