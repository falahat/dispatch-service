package dispatcher

import (
	"context"
	"reflect"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func TestSubmissionLookupAndSharedJobView(t *testing.T) {
	d, _ := newTestDispatcher(t)
	request := wire.EnqueueJob{JobKey: "same", Lane: "embed", InvocationAddress: invAddr("submission"), SubmissionKey: "first"}
	twin := request
	twin.SubmissionKey = "second"
	result, err := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{request, twin}})
	if err != nil || len(result.Results) != 2 || !result.Results[0].Created || result.Results[1].Created || result.Results[0].JobID != result.Results[1].JobID {
		t.Fatalf("one native execution for both submissions: %+v %v", result, err)
	}
	id := result.Results[0].JobID
	for _, key := range []string{"first", "second"} {
		if found, err := d.lookup(key); err != nil || found != id {
			t.Fatalf("exact lookup of %s: %s %v", key, found, err)
		}
	}
	hello(t, d, "worker", "embed")
	grant, _ := leaseOne(t, d, "worker", "embed")
	if err := d.Complete("worker", wire.Complete{JobID: id, LeaseID: grant.Lease.LeaseID, Attempt: 1, ActionResult: sampleResult(request.InvocationAddress)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Ack(wire.Ack{JobID: id, Disposition: wire.DispositionPersisted}); err != nil {
		t.Fatal(err)
	}
	view, werr := d.job(context.Background(), id, false)
	jobs, readErr := d.Jobs(JobsFilter{JobKeyPrefix: "same"})
	waited, waitErr := d.job(context.Background(), id, true)
	if werr != nil || readErr != nil || waitErr != nil || len(jobs.Jobs) != 1 || !reflect.DeepEqual(view, jobs.Jobs[0]) || !reflect.DeepEqual(view, waited) || len(view.ActionResult) == 0 {
		t.Fatalf("job, jobs and wait must expose the same complete view: %+v %+v %+v", view, jobs, waited)
	}
	replay, err := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{request}})
	if err != nil || replay.Results[0].Created || replay.Results[0].JobID != id {
		t.Fatalf("accepted submission survives terminal completion: %+v %v", replay, err)
	}
	request.InvocationAddress = invAddr("different")
	if _, err := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{request}}); err == nil || err.Code != wire.CodeConflict {
		t.Fatalf("a submission cannot silently change its request: %v", err)
	}
	if _, err := d.lookup("missing"); err == nil || err.Code != wire.CodeGone {
		t.Fatalf("missing submissions remain unknown: %v", err)
	}
}
