package dispatcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// SweepResult reports what a timer pass recovered.
type SweepResult struct {
	Recovered    int `json:"recovered"`     // expired leases requeued (presumed crash)
	Expired      int `json:"expired"`       // expired leases that hit max_attempts -> FAILED
	GCCandidates int `json:"gc_candidates"` // terminal jobs whose CAS pins are released
}

// Sweep runs the timer pass: expired leases are recovered. A silent death is
// presumed a crash, so lease_expired burns an attempt (attempt+1) — this is what
// catches crash-loops via the poison cap.
func (d *Dispatcher) Sweep() (SweepResult, error) {
	var out SweepResult
	err := d.store.writeTx(func(tx *sql.Tx) error {
		now := d.now()
		rows, err := tx.Query(
			`SELECT `+jobColumns+` FROM jobs WHERE state='RUNNING' AND lease_deadline_ts IS NOT NULL AND lease_deadline_ts < ?`,
			now)
		if err != nil {
			return err
		}
		var expired []Job
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				rows.Close()
				return err
			}
			expired = append(expired, j)
		}
		rows.Close()

		for _, j := range expired {
			if err := insertAttempt(tx, j.JobID, j.Attempt, j.LeaseRunnerID, j.LeaseID, "lease_expired", "", "deadline", 0, now); err != nil {
				return err
			}
			if j.Attempt < j.Policy.MaxAttempts {
				newAttempt := j.Attempt + 1
				nextAt := now + d.jitter(j.Policy, newAttempt)
				if _, err := tx.Exec(
					`UPDATE jobs SET state='QUEUED', attempt=?, next_attempt_at=?,
						lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
					 WHERE job_id=? AND lease_id=?`,
					newAttempt, nextAt, now, j.JobID, j.LeaseID); err != nil {
					return err
				}
				out.Recovered++
			} else {
				if _, err := tx.Exec(
					`UPDATE jobs SET state='FAILED', reason='lease_expired', lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
					 WHERE job_id=? AND lease_id=?`,
					now, j.JobID, j.LeaseID); err != nil {
					return err
				}
				if err := releaseReservation(tx, j.CostCents); err != nil {
					return err
				}
				out.Expired++
			}
		}

		// Informational: terminal jobs have released their CAS pins.
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM jobs WHERE state IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED')`).Scan(&out.GCCandidates); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return SweepResult{}, err
	}
	if out.Recovered > 0 {
		d.wakeLeases()
	}
	return out, nil
}

// RunSweeper runs the periodic sweep until ctx is cancelled.
func (d *Dispatcher) RunSweeper(ctx context.Context) {
	interval := time.Duration(d.cfg.SweepIntervalS) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = d.Sweep()
		}
	}
}

// PinnedAddresses returns the set of CAS addresses currently pinned by the
// dispatcher's live state: the invocation_address of every non-terminal job,
// plus every output address in a PERSISTING action result. The external GC
// deletes anything in the CAS not in this set (older than the orphan TTL). This
// is the pin view the retention contract (CAS.md) names.
func (d *Dispatcher) PinnedAddresses() (map[artifact.Address]bool, error) {
	pinned := map[artifact.Address]bool{}
	rows, err := d.store.db.Query(
		`SELECT invocation_address, state, result_json FROM jobs
		 WHERE state NOT IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var inv, state string
		var result sql.NullString
		if err := rows.Scan(&inv, &state, &result); err != nil {
			return nil, err
		}
		pinned[artifact.Address(inv)] = true
		if state == "PERSISTING" && result.Valid && result.String != "" {
			var ar artifact.ActionResult
			if json.Unmarshal([]byte(result.String), &ar) == nil {
				for _, o := range ar.Outputs {
					pinned[o.Address] = true
				}
			}
		}
	}
	return pinned, rows.Err()
}
