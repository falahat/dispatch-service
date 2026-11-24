package dispatcher

import (
	"context"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

// A retried job's log continues where its earlier attempts' ended: the grant says
// where, so the next attempt's first chunk follows the first attempt's instead of
// landing on it at offset 0, which the dispatcher refused as divergent, rolling
// back the heartbeat and its lease renewal with it (D16).
func TestRetriedJobsLogContinuesAfterItsEarlierAttempts(t *testing.T) {
	d, clk := newTestDispatcher(t)
	attempts := 2
	id := enqueueOne(t, d, "k", "embed", invAddr("j"), &wire.Policy{MaxAttempts: &attempts})
	hello(t, d, "R1", "embed")
	beat := func(g *wire.Grant, chunk wire.LogChunk) (wire.BeatOK, *wire.Error) {
		return d.Heartbeat("R1", wire.Heartbeat{
			Status:  wire.HeartbeatStatus{Node: "R1", Lanes: []string{"embed"}, Capacity: 1, CurrentJobID: id},
			LeaseID: g.Lease.LeaseID, Log: &chunk,
		})
	}

	first, _ := leaseOne(t, d, "R1", "embed")
	if first == nil || first.Job.LogOffset != 0 {
		t.Fatalf("first grant = %+v, want its log to start at 0", first)
	}
	if _, werr := beat(first, wire.LogChunk{Offset: 0, Address: invAddr("first try"), Size: 9}); werr != nil {
		t.Fatalf("first attempt's chunk: %v", werr)
	}
	if werr := d.Fail("R1", wire.Fail{LeaseID: first.Lease.LeaseID, JobID: id, Attempt: 1, ErrorClass: wire.ClassNetwork, Message: "down"}); werr != nil {
		t.Fatalf("fail: %v", werr)
	}
	job, _ := d.GetJob(id)
	clk.Set(job.NextAttemptAt + 1)
	heardFrom(t, d, "R1")

	second, _ := leaseOne(t, d, "R1", "embed")
	if second == nil || second.Job.LogOffset != 9 {
		t.Fatalf("second grant = %+v, want its log to continue at 9", second)
	}
	ok, werr := beat(second, wire.LogChunk{Offset: 9, Address: invAddr("second try, longer"), Size: 18})
	if werr != nil || ok.LogOffset == nil || *ok.LogOffset != 27 {
		t.Fatalf("second attempt's chunk: beat %+v, err %v", ok, werr)
	}
	got, werr := d.logs(context.Background(), logsRequest{JobID: id})
	if werr != nil || len(got.Entries) != 2 || got.Entries[1].Offset != 9 || got.NextOffset != 27 {
		t.Fatalf("job log = %+v (err %v), want both attempts' chunks in order", got, werr)
	}
}
