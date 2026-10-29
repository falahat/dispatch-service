package dispatcher

import (
	"context"
	"database/sql"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Waiting clients have their own connections; none takes over the app's durable
// completion subscription. Capture the wake channel before reading to avoid races.
func (d *Dispatcher) job(ctx context.Context, id string, wait bool) (JobView, *wire.Error) {
	if !jobIDRe.MatchString(id) {
		return JobView{}, &wire.Error{Code: wire.CodeInvalid, Message: "malformed job_id"}
	}
	for {
		wake := d.leaseWake.wait()
		job, err := d.GetJob(id)
		if err == sql.ErrNoRows {
			return JobView{}, &wire.Error{Code: wire.CodeGone, Message: "unknown job"}
		}
		if err != nil {
			return JobView{}, &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
		}
		pending := job.State == "QUEUED" || job.State == "RUNNING" || job.State == "AWAITING_APPROVAL"
		pending = pending || d.cfg.WaitForExecutor && job.State == "PERSISTING"
		if !wait || !pending {
			result, err := d.jobView(job)
			if err != nil {
				return result, &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
			}
			return result, nil
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return JobView{}, &wire.Error{Code: wire.CodeGone, Message: "dispatcher shutting down"}
		}
	}
}

func (d *Dispatcher) lookup(key string) (string, *wire.Error) {
	if key == "" || len(key) > 256 {
		return "", &wire.Error{Code: wire.CodeInvalid, Message: "invalid submission_key"}
	}
	var id string
	err := d.store.db.QueryRow(`SELECT job_id FROM submissions WHERE submission_key=?`, key).Scan(&id)
	if err == sql.ErrNoRows {
		return "", &wire.Error{Code: wire.CodeGone, Message: "unknown submission"}
	}
	if err != nil {
		return "", &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
	}
	return id, nil
}
