package dispatcher

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Enqueue creates jobs idempotently. The whole batch is one transaction: either
// every job is placed or (on a budget reservation failure for a priced job) the
// batch is rejected with error{budget}, leaving no partial state. Idempotency:
// an existing LIVE job with the same job_key yields its job_id with created=false
// and all other fields ignored; terminal jobs do not block key re-use.
func (d *Dispatcher) Enqueue(req wire.Enqueue) (wire.EnqueueResult, *wire.Error) {
	if len(req.Jobs) == 0 || len(req.Jobs) > 256 {
		return wire.EnqueueResult{}, &wire.Error{Code: wire.CodeInvalid, Message: "enqueue: 1..256 jobs required"}
	}
	var out wire.EnqueueResult
	var budgetErr *wire.Error

	err := d.store.writeTx(func(tx *sql.Tx) error {
		now := d.now()
		batchKeys := map[string]wire.EnqueueResultItem{} // dedup within the batch
		for _, ej := range req.Jobs {
			if item, ok := batchKeys[ej.JobKey]; ok {
				out.Results = append(out.Results, wire.EnqueueResultItem{JobKey: ej.JobKey, JobID: item.JobID, Created: false})
				continue
			}
			if err := validateEnqueueJob(ej); err != nil {
				budgetErr = &wire.Error{Code: wire.CodeInvalid, Message: err.Error()}
				return errAbortBatch
			}
			// Idempotency: is there a live job for this key?
			existing, err := liveJobIDForKey(tx, ej.JobKey)
			if err != nil {
				return err
			}
			if existing != "" {
				item := wire.EnqueueResultItem{JobKey: ej.JobKey, JobID: existing, Created: false}
				out.Results = append(out.Results, item)
				batchKeys[ej.JobKey] = item
				continue
			}

			pol := ResolvePolicy(ej.Policy)
			if d.cfg.Lane(ej.Lane).SingleAttempt {
				pol.MaxAttempts, pol.ReleaseCap = 1, 1
			}
			cost, err := parseUSD(ej.CostEstimateUSD)
			if err != nil {
				budgetErr = &wire.Error{Code: wire.CodeInvalid, Message: "enqueue: " + err.Error()}
				return errAbortBatch
			}

			state := "QUEUED"
			if cost > 0 {
				ok, err := reserveBudget(tx, cost)
				if err != nil {
					return err
				}
				if !ok {
					budgetErr = &wire.Error{Code: wire.CodeBudget, Message: fmt.Sprintf("enqueue: budget reservation failed for job_key %q ($%s)", ej.JobKey, cost.String())}
					return errAbortBatch
				}
				state = "AWAITING_APPROVAL"
			}

			jobID := d.ids.JobID(now)
			if err := insertJob(tx, jobID, ej, pol, cost, state, now); err != nil {
				return err
			}
			if err := insertAttempt(tx, jobID, 0, "", "", "enqueue", "", state, now, now); err != nil {
				return err
			}
			item := wire.EnqueueResultItem{JobKey: ej.JobKey, JobID: jobID, Created: true}
			out.Results = append(out.Results, item)
			batchKeys[ej.JobKey] = item
		}
		return nil
	})

	if errors.Is(err, errAbortBatch) {
		return wire.EnqueueResult{}, budgetErr
	}
	if err != nil {
		return wire.EnqueueResult{}, &wire.Error{Code: wire.CodeInternal, Message: "enqueue: " + err.Error()}
	}
	// New QUEUED work may exist; wake any blocked lease long-polls.
	d.wakeLeases()
	return out, nil
}

var errAbortBatch = errors.New("abort batch")

func validateEnqueueJob(ej wire.EnqueueJob) error {
	if len(ej.JobKey) < 1 || len(ej.JobKey) > 256 {
		return fmt.Errorf("enqueue: job_key length invalid")
	}
	if !laneRe.MatchString(ej.Lane) {
		return fmt.Errorf("enqueue: invalid lane %q", ej.Lane)
	}
	if err := ej.InvocationAddress.Validate(); err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	if ej.Policy != nil {
		if err := validatePolicy(ej.Policy); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicy(p *wire.Policy) error {
	if p.MaxAttempts != nil && (*p.MaxAttempts < 1 || *p.MaxAttempts > 10) {
		return errors.New("enqueue: max_attempts out of range")
	}
	if p.Priority != nil && (*p.Priority < 0 || *p.Priority > 9) {
		return errors.New("enqueue: priority out of range")
	}
	if p.ReleaseCap != nil && (*p.ReleaseCap < 1 || *p.ReleaseCap > 20) {
		return errors.New("enqueue: release_cap out of range")
	}
	if p.BackoffClass != nil {
		switch *p.BackoffClass {
		case wire.BackoffQuick, wire.BackoffStandard, wire.BackoffLong:
		default:
			return errors.New("enqueue: invalid backoff_class")
		}
	}
	return nil
}

// liveJobIDForKey returns the job_id of the live (non-terminal) job for key, or
// "" if none.
func liveJobIDForKey(tx *sql.Tx, key string) (string, error) {
	var id string
	err := tx.QueryRow(
		`SELECT job_id FROM jobs WHERE job_key=? AND state NOT IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED')`,
		key).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func insertJob(tx *sql.Tx, jobID string, ej wire.EnqueueJob, pol ResolvedPolicy, cost Money, state string, now int64) error {
	overrides := "{}"
	if pol.ErrorClassOverrides != nil {
		b, _ := json.Marshal(pol.ErrorClassOverrides)
		overrides = string(b)
	}
	// attempt starts at 1: it is the current try number (states.json increments
	// it on fail/lease_expired, never at claim), so a job has had `attempt`
	// tries and max_attempts caps them.
	_, err := tx.Exec(
		`INSERT INTO jobs(job_id, job_key, lane, invocation_address, state, attempt, release_count,
			priority, max_attempts, backoff_class, release_cap, expected_wall_s, error_class_overrides,
			cost_cents, next_attempt_at, created_ts, updated_ts)
		 VALUES(?,?,?,?,?,1,0,?,?,?,?,?,?,?,?,?,?)`,
		jobID, ej.JobKey, ej.Lane, string(ej.InvocationAddress), state,
		pol.Priority, pol.MaxAttempts, string(pol.BackoffClass), pol.ReleaseCap, pol.ExpectedWallS, overrides,
		int64(cost), now, now, now)
	return err
}

// reserveBudget attempts to reserve cost against the remaining budget. Returns
// (false, nil) when the cap is insufficient (fail-closed at $0 default).
func reserveBudget(tx *sql.Tx, cost Money) (bool, error) {
	var cap, reserved, spent int64
	if err := tx.QueryRow(`SELECT cap_cents, reserved_cents, spent_cents FROM budget WHERE id=1`).Scan(&cap, &reserved, &spent); err != nil {
		return false, err
	}
	if reserved+spent+int64(cost) > cap {
		return false, nil
	}
	_, err := tx.Exec(`UPDATE budget SET reserved_cents=reserved_cents+? WHERE id=1`, int64(cost))
	return err == nil, err
}

// releaseReservation returns a reservation to the pool (reject/cancel/terminal-without-spend).
func releaseReservation(tx *sql.Tx, cost Money) error {
	if cost <= 0 {
		return nil
	}
	_, err := tx.Exec(`UPDATE budget SET reserved_cents=MAX(0, reserved_cents-?) WHERE id=1`, int64(cost))
	return err
}

// commitSpend moves a reservation to spent (a priced job SUCCEEDED).
func commitSpend(tx *sql.Tx, cost Money) error {
	if cost <= 0 {
		return nil
	}
	_, err := tx.Exec(`UPDATE budget SET reserved_cents=MAX(0, reserved_cents-?), spent_cents=spent_cents+? WHERE id=1`, int64(cost), int64(cost))
	return err
}
