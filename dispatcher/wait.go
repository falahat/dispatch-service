package dispatcher

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/falahat/dispatch-service/internal/wire"
)

type jobRequest struct {
	JobID string `json:"job_id"`
}

// Waiting clients have their own connections; none takes over the app's durable
// completion subscription. Capture the wake channel before reading to avoid races.
func (d *Dispatcher) job(ctx context.Context, id string, wait bool) (map[string]any, *wire.Error) {
	if !jobIDRe.MatchString(id) {
		return nil, &wire.Error{Code: wire.CodeInvalid, Message: "malformed job_id"}
	}
	for {
		wake := d.leaseWake.wait()
		job, err := d.GetJob(id)
		if err != nil {
			return nil, &wire.Error{Code: wire.CodeGone, Message: "unknown job"}
		}
		pending := job.State == "QUEUED" || job.State == "RUNNING" || job.State == "AWAITING_APPROVAL"
		pending = pending || d.cfg.WaitForExecutor && job.State == "PERSISTING"
		pending = pending || d.cfg.WaitForExecutor && job.State == "CANCELLED" && job.CancelRequested
		if !wait || !pending {
			result := map[string]any{"job_id": job.JobID, "job_key": job.JobKey, "state": job.State,
				"invocation_address": job.InvocationAddress, "runner_id": job.LeaseRunnerID, "reason": job.Reason,
				"attempt": job.Attempt, "release_count": job.ReleaseCount}
			if job.ResultJSON != "" {
				result["action_result"] = json.RawMessage(job.ResultJSON)
			}
			return result, nil
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return nil, &wire.Error{Code: wire.CodeGone, Message: "dispatcher shutting down"}
		}
	}
}

// ExecutionSettled is called only after the local executor has reaped its child.
// A cancellation request is not proof that the cancelled execution has stopped.
func (d *Dispatcher) ExecutionSettled(id string) error {
	return d.store.writeTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE jobs SET cancel_requested=0 WHERE job_id=? AND state='CANCELLED'", id)
		return err
	})
}
