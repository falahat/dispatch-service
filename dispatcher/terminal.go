package dispatcher

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

// batchScaleFloor is the smallest batch_scale an OOM feedback loop will emit.
const batchScaleFloor = 0.0625

// Complete moves a RUNNING job to PERSISTING (the durable inbox), storing the
// action result and waking the app subscription. Fenced by lease_id; idempotent
// per (job_id, attempt): an exact replay returns ok, a divergent one conflicts.
func (d *Dispatcher) Complete(runnerID string, req wire.Complete) *wire.Error {
	if !jobIDRe.MatchString(req.JobID) || !leaseIDRe.MatchString(req.LeaseID) {
		return &wire.Error{Code: wire.CodeInvalid, Message: "complete: malformed ids"}
	}
	if err := req.ActionResult.Validate(); err != nil {
		return &wire.Error{Code: wire.CodeInvalid, Message: "complete: " + err.Error()}
	}
	incoming, _ := json.Marshal(req.ActionResult)

	var outErr *wire.Error
	err := d.store.writeTx(func(tx *sql.Tx) error {
		job, err := getJobTx(tx, req.JobID)
		if err == sql.ErrNoRows {
			outErr = &wire.Error{Code: wire.CodeGone, Message: "complete: unknown job"}
			return nil
		}
		if err != nil {
			return err
		}

		// Idempotent replay: this attempt already completed.
		if job.ResultJSON != "" && job.ResultAttempt == req.Attempt {
			if jsonEqualBytes([]byte(job.ResultJSON), incoming) {
				return nil // exact replay -> ok
			}
			outErr = &wire.Error{Code: wire.CodeConflict, Message: "complete: divergent replay for this attempt"}
			return nil
		}

		// Live-leaseholder path.
		if job.State == "RUNNING" && job.LeaseID == req.LeaseID && job.Attempt == req.Attempt {
			// The runner echoes invocation_address from its grant; it must match.
			if string(req.ActionResult.InvocationAddress) != job.InvocationAddress {
				outErr = &wire.Error{Code: wire.CodeInvalid, Message: "complete: invocation_address does not match grant"}
				return nil
			}
			now := d.now()
			if _, err := tx.Exec(
				`UPDATE jobs SET state='PERSISTING', result_json=?, result_attempt=?, completed_ts=?,
					lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
				 WHERE job_id=? AND state='RUNNING' AND lease_id=?`,
				string(incoming), req.Attempt, now, now, req.JobID, req.LeaseID); err != nil {
				return err
			}
			if err := insertAttempt(tx, req.JobID, req.Attempt, runnerID, req.LeaseID, "complete", "", "", 0, now); err != nil {
				return err
			}
			return nil
		}

		// Anything else is a stale/foreign leaseholder.
		outErr = &wire.Error{Code: wire.CodeNotLeaseholder, Message: "complete: not the live leaseholder"}
		return nil
	})
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "complete: " + err.Error()}
	}
	if outErr == nil {
		// A new PERSISTING item may exist; wake the subscription and free a lane slot.
		d.subs.notify()
		d.wakeLeases()
	}
	return outErr
}

// Fail burns an attempt. The job's policy maps the error_class to retriable
// (backoff + requeue, with an OOM batch_scale hint) or terminal (dead-letter).
// Fenced by lease_id; idempotent per (job_id, attempt).
func (d *Dispatcher) Fail(runnerID string, req wire.Fail) *wire.Error {
	if !jobIDRe.MatchString(req.JobID) || !leaseIDRe.MatchString(req.LeaseID) {
		return &wire.Error{Code: wire.CodeInvalid, Message: "fail: malformed ids"}
	}
	if !wire.ValidErrorClasses[req.ErrorClass] {
		return &wire.Error{Code: wire.CodeInvalid, Message: "fail: unknown error_class"}
	}

	var outErr *wire.Error
	requeued := false
	err := d.store.writeTx(func(tx *sql.Tx) error {
		job, err := getJobTx(tx, req.JobID)
		if err == sql.ErrNoRows {
			outErr = &wire.Error{Code: wire.CodeGone, Message: "fail: unknown job"}
			return nil
		}
		if err != nil {
			return err
		}

		// Idempotent replay: this attempt already recorded a terminal verb.
		done, err := attemptSettled(tx, req.JobID, req.Attempt)
		if err != nil {
			return err
		}
		if !(job.State == "RUNNING" && job.LeaseID == req.LeaseID && job.Attempt == req.Attempt) {
			if done {
				return nil // already handled -> ok
			}
			outErr = &wire.Error{Code: wire.CodeNotLeaseholder, Message: "fail: not the live leaseholder"}
			return nil
		}

		now := d.now()
		if err := insertAttempt(tx, req.JobID, req.Attempt, runnerID, req.LeaseID, "fail", string(req.ErrorClass), req.Message, 0, now); err != nil {
			return err
		}

		retriable := job.Policy.IsRetriable(req.ErrorClass) && job.Attempt < job.Policy.MaxAttempts
		if retriable {
			newAttempt := job.Attempt + 1
			backoff := d.jitter(job.Policy, newAttempt)
			nextAt := now + backoff
			batch := job.BatchScale
			if req.ErrorClass == wire.ClassOOM {
				batch = halveScale(job.BatchScale)
			}
			if _, err := tx.Exec(
				`UPDATE jobs SET state='QUEUED', attempt=?, next_attempt_at=?, batch_scale=?,
					lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
				 WHERE job_id=? AND state='RUNNING' AND lease_id=?`,
				newAttempt, nextAt, batch, now, req.JobID, req.LeaseID); err != nil {
				return err
			}
			requeued = true
			return nil
		}

		// Terminal: dead-letter with the attempt timeline; refund any reservation.
		reason := "fail:" + string(req.ErrorClass)
		if _, err := tx.Exec(
			`UPDATE jobs SET state='FAILED', reason=?, lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
			 WHERE job_id=? AND state='RUNNING' AND lease_id=?`,
			reason, now, req.JobID, req.LeaseID); err != nil {
			return err
		}
		return releaseReservation(tx, job.CostCents)
	})
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "fail: " + err.Error()}
	}
	if outErr == nil && requeued {
		d.wakeLeases()
	}
	return outErr
}

// Release returns a job that could not be started/shipped to QUEUED with the
// attempt UNCHANGED (no compute happened). A release_count at the cap for that
// reason's class (ResolvedPolicy.ReleaseCapFor) dead-letters the job as FAILED,
// carrying the reason forward so the app can tell an evicted input from a dead
// CAS. Fenced by lease_id; idempotent per lease.
func (d *Dispatcher) Release(runnerID string, req wire.Release) *wire.Error {
	if !jobIDRe.MatchString(req.JobID) || !leaseIDRe.MatchString(req.LeaseID) {
		return &wire.Error{Code: wire.CodeInvalid, Message: "release: malformed ids"}
	}
	if !wire.ValidReleaseReasons[req.Reason] {
		return &wire.Error{Code: wire.CodeInvalid, Message: "release: unknown reason"}
	}

	var outErr *wire.Error
	requeued := false
	err := d.store.writeTx(func(tx *sql.Tx) error {
		job, err := getJobTx(tx, req.JobID)
		if err == sql.ErrNoRows {
			outErr = &wire.Error{Code: wire.CodeGone, Message: "release: unknown job"}
			return nil
		}
		if err != nil {
			return err
		}

		if !(job.State == "RUNNING" && job.LeaseID == req.LeaseID) {
			// Idempotent replay: this exact lease already released.
			seen, err := leaseReleased(tx, req.JobID, req.LeaseID)
			if err != nil {
				return err
			}
			if seen {
				return nil
			}
			outErr = &wire.Error{Code: wire.CodeNotLeaseholder, Message: "release: not the live leaseholder"}
			return nil
		}

		now := d.now()
		if err := insertAttempt(tx, req.JobID, job.Attempt, runnerID, req.LeaseID, "release", "", string(req.Reason), 0, now); err != nil {
			return err
		}
		newReleaseCount := job.ReleaseCount + 1
		// The cap depends on WHY. Infrastructure noise (CAS unreachable, a failed output
		// upload) must not burn the same tiny poison budget as a verdict about this job.
		if newReleaseCount >= job.Policy.ReleaseCapFor(req.Reason) {
			// Preserve the distinguishing reason instead of collapsing every cause to
			// 'unstartable'. The app reads this to decide what to DO, and a cas_miss — a
			// content-addressed input that aged out of the CAS — is trivially fixable by
			// re-staging the bytes it still holds. Collapsing the reason erased that.
			if _, err := tx.Exec(
				`UPDATE jobs SET state='FAILED', release_count=?, reason=?,
					lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
				 WHERE job_id=? AND state='RUNNING' AND lease_id=?`,
				newReleaseCount, deadLetterReason(req.Reason), now, req.JobID, req.LeaseID); err != nil {
				return err
			}
			return releaseReservation(tx, job.CostCents)
		}
		// Re-queue, attempt unchanged. Pace re-tries so a persistent
		// can't-start condition doesn't hot-loop toward the cap.
		delay := int64(1000) << minInt(newReleaseCount, 5) // 1s,2s,...,32s
		if _, err := tx.Exec(
			`UPDATE jobs SET state='QUEUED', release_count=?, next_attempt_at=?,
				lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
			 WHERE job_id=? AND state='RUNNING' AND lease_id=?`,
			newReleaseCount, now+delay, now, req.JobID, req.LeaseID); err != nil {
			return err
		}
		requeued = true
		return nil
	})
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "release: " + err.Error()}
	}
	if outErr == nil && requeued {
		d.wakeLeases()
	}
	return outErr
}

// attemptSettled reports whether a terminal verb (complete/fail) was already
// recorded for (job_id, attempt) — the idempotency check for replays.
func attemptSettled(tx *sql.Tx, jobID string, attempt int) (bool, error) {
	var n int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM attempts WHERE job_id=? AND attempt=? AND outcome IN ('complete','fail')`,
		jobID, attempt).Scan(&n)
	return n > 0, err
}

// leaseReleased reports whether this lease already recorded a release.
func leaseReleased(tx *sql.Tx, jobID, leaseID string) (bool, error) {
	var n int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM attempts WHERE job_id=? AND lease_id=? AND outcome='release'`,
		jobID, leaseID).Scan(&n)
	return n > 0, err
}

// halveScale halves a batch_scale decimal-as-string (default 1.0), flooring at
// batchScaleFloor, formatted to match the wire pattern.
func halveScale(cur string) string {
	v := 1.0
	if cur != "" {
		if f, err := strconv.ParseFloat(cur, 64); err == nil {
			v = f
		}
	}
	v /= 2
	if v < batchScaleFloor {
		v = batchScaleFloor
	}
	// Format with up to 4 decimals, trimming trailing zeros.
	s := strconv.FormatFloat(v, 'f', 4, 64)
	for len(s) > 3 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	return s
}

func jsonEqualBytes(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xb) == string(yb)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// deadLetterReason is the terminal reason recorded when releases hit the cap.
//
// Everything used to collapse to "unstartable", which threw away the only
// information the app needed to act. cas_miss in particular is not a dead end: the
// input is content-addressed and the app still holds the source bytes, so naming it
// distinctly lets the app re-stage and re-enqueue rather than surface a permanent
// failure to the owner.
func deadLetterReason(reason wire.ReleaseReason) string {
	if reason == wire.ReleaseCASMiss {
		return "input_evicted"
	}
	return "unstartable:" + string(reason)
}

// buildCompletion reconstructs the wire.Completion for a PERSISTING job from its
// stored action result. Used by the subscription stream.
func buildCompletion(j Job) (wire.Completion, error) {
	var ar artifact.ActionResult
	if err := json.Unmarshal([]byte(j.ResultJSON), &ar); err != nil {
		return wire.Completion{}, fmt.Errorf("completion: corrupt result_json for %s: %w", j.JobID, err)
	}
	return wire.Completion{
		JobID:        j.JobID,
		JobKey:       j.JobKey,
		Lane:         j.Lane,
		Attempt:      j.ResultAttempt,
		ActionResult: ar,
		CompletedTS:  j.CompletedTS,
	}, nil
}
