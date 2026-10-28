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
	Pruned       int `json:"pruned"`        // terminal jobs deleted by the retention window (0 = no TTL)
}

// retentionBatch bounds how many terminal jobs one sweep prunes, so a large
// backlog drains over several passes without holding a long write lock.
const retentionBatch = 500

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

		// Retention: prune terminal jobs (and their attempts) older than the window.
		// Off by default (JobRetentionDays 0 = keep forever); touches only this
		// re-derivable queue history, never domain data.
		pruned, err := d.pruneRetiredJobs(tx, now)
		if err != nil {
			return err
		}
		out.Pruned = pruned

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
	if out.Recovered > 0 || out.Expired > 0 {
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

// pruneRetiredJobs deletes a bounded batch of terminal jobs (and their attempt
// rows) whose last update is older than the retention window. JobRetentionDays 0
// keeps everything (no TTL — the default). Terminal = SUCCEEDED/FAILED/REJECTED/
// CANCELLED only — never PERSISTING (still awaiting the app's ack) or any live
// state, and never any domain data (transcripts / analysis results live in the
// app's own store, not here). One bounded batch per sweep drains a large backlog
// over several passes without holding a long write lock.
func (d *Dispatcher) pruneRetiredJobs(tx *sql.Tx, now int64) (int, error) {
	if d.cfg.JobRetentionDays <= 0 {
		return 0, nil
	}
	cutoff := now - int64(d.cfg.JobRetentionDays)*86_400_000
	rows, err := tx.Query(
		`SELECT job_id FROM jobs
		 WHERE state IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED') AND updated_ts < ?
		 ORDER BY updated_ts LIMIT ?`, cutoff, retentionBatch)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM attempts WHERE job_id=?`, id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`DELETE FROM jobs WHERE job_id=?`, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
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
