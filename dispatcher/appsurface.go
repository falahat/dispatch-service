package dispatcher

import (
	"database/sql"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Ack settles a PERSISTING job. `persisted` -> SUCCEEDED (unpins the job's CAS
// blobs); `rejected` (the app parsed the output as garbage) -> FAILED(bad_output),
// dead-lettered. Idempotent; only meaningful from PERSISTING.
func (d *Dispatcher) Ack(req wire.Ack) *wire.Error {
	if !jobIDRe.MatchString(req.JobID) {
		return &wire.Error{Code: wire.CodeInvalid, Message: "ack: malformed job_id"}
	}
	if req.Disposition != wire.DispositionPersisted && req.Disposition != wire.DispositionRejected {
		return &wire.Error{Code: wire.CodeInvalid, Message: "ack: invalid disposition"}
	}
	var outErr *wire.Error
	err := d.store.writeTx(func(tx *sql.Tx) error {
		job, err := getJobTx(tx, req.JobID)
		if err == sql.ErrNoRows {
			outErr = &wire.Error{Code: wire.CodeGone, Message: "ack: unknown job"}
			return nil
		}
		if err != nil {
			return err
		}
		if job.State != "PERSISTING" {
			// Idempotent: acking an already-settled job in the matching terminal
			// state is a no-op ok.
			switch {
			case req.Disposition == wire.DispositionPersisted && job.State == "SUCCEEDED":
				return nil
			case req.Disposition == wire.DispositionRejected && job.State == "FAILED" && job.Reason == "bad_output":
				return nil
			default:
				outErr = &wire.Error{Code: wire.CodeInvalid, Message: "ack: job not in PERSISTING"}
				return nil
			}
		}
		now := d.now()
		if req.Disposition == wire.DispositionPersisted {
			if _, err := tx.Exec(`UPDATE jobs SET state='SUCCEEDED', updated_ts=? WHERE job_id=? AND state='PERSISTING'`, now, req.JobID); err != nil {
				return err
			}
			if err := commitSpend(tx, job.CostCents); err != nil {
				return err
			}
			if err := insertAttempt(tx, req.JobID, job.ResultAttempt, "", "", "ack", "", "persisted", 0, now); err != nil {
				return err
			}
			return evaluateQuarantineOnSuccess(tx, req.JobID)
		}
		// rejected
		if _, err := tx.Exec(`UPDATE jobs SET state='FAILED', reason='bad_output', updated_ts=? WHERE job_id=? AND state='PERSISTING'`, now, req.JobID); err != nil {
			return err
		}
		if err := releaseReservation(tx, job.CostCents); err != nil {
			return err
		}
		return insertAttempt(tx, req.JobID, job.ResultAttempt, "", "", "ack", "", "rejected", 0, now)
	})
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "ack: " + err.Error()}
	}
	if outErr == nil {
		d.wakeLeases() // draining the inbox may clear backpressure
	}
	return outErr
}

// evaluateQuarantineOnSuccess implements the two-witness rule: a runner that
// FAILED this job, which then SUCCEEDED on a DIFFERENT runner, accrues a
// corroborated failure. At the threshold it is quarantined. The corroboration
// requirement means a single-runner lane can never starve itself.
func evaluateQuarantineOnSuccess(tx *sql.Tx, jobID string) error {
	var succeeder sql.NullString
	if err := tx.QueryRow(
		`SELECT runner_id FROM attempts WHERE job_id=? AND outcome='complete' ORDER BY id DESC LIMIT 1`,
		jobID).Scan(&succeeder); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	rows, err := tx.Query(
		`SELECT DISTINCT runner_id FROM attempts WHERE job_id=? AND outcome='fail' AND runner_id IS NOT NULL AND runner_id != ?`,
		jobID, succeeder.String)
	if err != nil {
		return err
	}
	var failers []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return err
		}
		failers = append(failers, r)
	}
	rows.Close()
	for _, r := range failers {
		var n int
		if err := tx.QueryRow(
			`UPDATE runners SET corroborated_failures = corroborated_failures + 1 WHERE runner_id=? RETURNING corroborated_failures`,
			r).Scan(&n); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return err
		}
		if n >= quarantineThreshold {
			if _, err := tx.Exec(
				`UPDATE runners SET quarantined=1, quarantine_reason='two_witness' WHERE runner_id=?`, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Approve moves a priced job from AWAITING_APPROVAL to QUEUED (reservation held).
func (d *Dispatcher) Approve(req wire.Approval) *wire.Error {
	return d.decideApproval(req, true)
}

// Reject moves a priced job to REJECTED and releases its reservation.
func (d *Dispatcher) Reject(req wire.Approval) *wire.Error {
	return d.decideApproval(req, false)
}

func (d *Dispatcher) decideApproval(req wire.Approval, approve bool) *wire.Error {
	if !jobIDRe.MatchString(req.JobID) {
		return &wire.Error{Code: wire.CodeInvalid, Message: "approval: malformed job_id"}
	}
	if req.Author == "" {
		return &wire.Error{Code: wire.CodeInvalid, Message: "approval: author required"}
	}
	action := "approve"
	if !approve {
		action = "reject"
	}
	var outErr *wire.Error
	requeued := false
	err := d.store.writeTx(func(tx *sql.Tx) error {
		job, err := getJobTx(tx, req.JobID)
		if err == sql.ErrNoRows {
			outErr = &wire.Error{Code: wire.CodeGone, Message: "approval: unknown job"}
			return nil
		}
		if err != nil {
			return err
		}
		now := d.now()
		if job.State != "AWAITING_APPROVAL" {
			// Idempotency: re-approving an already-queued/running job, or
			// re-rejecting a rejected one, is a no-op ok.
			if approve && job.State != "REJECTED" && job.State != "CANCELLED" {
				return nil
			}
			if !approve && job.State == "REJECTED" {
				return nil
			}
			outErr = &wire.Error{Code: wire.CodeInvalid, Message: "approval: job not awaiting approval"}
			return nil
		}
		if _, err := tx.Exec(`INSERT INTO approvals(job_id, author, reason, action, ts) VALUES(?,?,?,?,?)`,
			req.JobID, req.Author, req.Reason, action, now); err != nil {
			return err
		}
		if approve {
			if _, err := tx.Exec(`UPDATE jobs SET state='QUEUED', updated_ts=? WHERE job_id=? AND state='AWAITING_APPROVAL'`, now, req.JobID); err != nil {
				return err
			}
			requeued = true
			return nil
		}
		if _, err := tx.Exec(`UPDATE jobs SET state='REJECTED', reason='rejected', updated_ts=? WHERE job_id=? AND state='AWAITING_APPROVAL'`, now, req.JobID); err != nil {
			return err
		}
		return releaseReservation(tx, job.CostCents)
	})
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "approval: " + err.Error()}
	}
	if outErr == nil && requeued {
		d.wakeLeases()
	}
	return outErr
}

// Cancel moves any non-terminal job to CANCELLED. RUNNING jobs are voided (the
// runner learns via an abandon directive on its next heartbeat); PERSISTING jobs
// are removed from the inbox; reservations and CAS pins are released.
func (d *Dispatcher) Cancel(req wire.Cancel) *wire.Error {
	if !jobIDRe.MatchString(req.JobID) {
		return &wire.Error{Code: wire.CodeInvalid, Message: "cancel: malformed job_id"}
	}
	var outErr *wire.Error
	err := d.store.writeTx(func(tx *sql.Tx) error {
		job, err := getJobTx(tx, req.JobID)
		if err == sql.ErrNoRows {
			outErr = &wire.Error{Code: wire.CodeGone, Message: "cancel: unknown job"}
			return nil
		}
		if err != nil {
			return err
		}
		now := d.now()
		switch job.State {
		case "SUCCEEDED", "FAILED", "REJECTED":
			outErr = &wire.Error{Code: wire.CodeInvalid, Message: "cancel: job already terminal"}
			return nil
		case "CANCELLED":
			return nil // idempotent
		case "RUNNING":
			// Void the lease and mark cancelled; the heartbeat path abandons it.
			if _, err := tx.Exec(
				`UPDATE jobs SET state='CANCELLED', reason=?, cancel_requested=1,
					lease_id=NULL, lease_deadline_ts=NULL, lease_runner_id=NULL, updated_ts=?
				 WHERE job_id=? AND state='RUNNING'`, cancelReason(req.Reason), now, req.JobID); err != nil {
				return err
			}
		default: // AWAITING_APPROVAL, QUEUED, PERSISTING
			if _, err := tx.Exec(
				`UPDATE jobs SET state='CANCELLED', reason=?, result_json=NULL, updated_ts=? WHERE job_id=?`,
				cancelReason(req.Reason), now, req.JobID); err != nil {
				return err
			}
		}
		if err := insertAttempt(tx, req.JobID, job.Attempt, "", "", "cancel", "", req.Reason, 0, now); err != nil {
			return err
		}
		return releaseReservation(tx, job.CostCents)
	})
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "cancel: " + err.Error()}
	}
	if outErr == nil {
		d.wakeLeases()
	}
	return outErr
}

func cancelReason(r string) string {
	if r == "" {
		return "cancelled"
	}
	return "cancelled:" + r
}
