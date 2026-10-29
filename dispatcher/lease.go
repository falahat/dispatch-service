package dispatcher

import (
	"context"
	"database/sql"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

// pollInterval bounds how long a lease long-poll sleeps before re-checking
// time-based readiness (a backed-off job whose next_attempt_at has passed is
// not signalled by any event). Event-driven wakeups (enqueue, requeue, ack)
// are immediate via the broadcaster; this only bounds the backoff-ready latency.
const pollInterval = 750 * time.Millisecond

type claimOutcome int

const (
	claimNoWork claimOutcome = iota
	claimGranted
	claimBackpressure
	claimQuarantined
	claimDrained
	claimRateLimited
)

type claimResult struct {
	outcome     claimOutcome
	grant       wire.Grant
	retryAfterS int
}

// Lease is the runner's long-poll: it blocks up to the clamped wait for a job
// runnable in one of the requested lanes, returning a grant or an empty reason.
// ctx cancellation (server shutdown / client disconnect) unblocks it promptly.
func (d *Dispatcher) Lease(ctx context.Context, runnerID string, req wire.Lease) (*wire.Grant, *wire.Empty, *wire.Error) {
	if len(req.Lanes) == 0 || len(req.Lanes) > 32 {
		return nil, nil, &wire.Error{Code: wire.CodeInvalid, Message: "lease: 1..32 lanes required"}
	}
	for _, l := range req.Lanes {
		if !laneRe.MatchString(l) {
			return nil, nil, &wire.Error{Code: wire.CodeInvalid, Message: "lease: invalid lane " + l}
		}
	}
	deadline := time.Now().Add(d.clampWait(req.WaitS))
	for {
		wake := d.leaseWake.wait() // grab before claim to avoid a missed signal
		res, werr := d.tryClaim(runnerID, req.Lanes)
		if werr != nil {
			return nil, nil, werr
		}
		switch res.outcome {
		case claimGranted:
			return &res.grant, nil, nil
		case claimBackpressure:
			return nil, &wire.Empty{Reason: "backpressure", RetryAfterS: intptr(res.retryAfterS)}, nil
		case claimQuarantined:
			return nil, &wire.Empty{}, nil // quarantined runners silently get empty
		case claimDrained:
			return nil, &wire.Empty{Reason: "drained"}, nil
		case claimRateLimited:
			return nil, &wire.Empty{RetryAfterS: intptr(res.retryAfterS)}, nil
		case claimNoWork:
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, &wire.Empty{}, nil
			}
			sleep := remaining
			if sleep > pollInterval {
				sleep = pollInterval
			}
			t := time.NewTimer(sleep)
			select {
			case <-wake:
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return nil, &wire.Empty{}, nil
			}
			t.Stop()
		}
	}
}

// tryClaim performs one atomic claim attempt. Because the store serializes
// writers (single connection, IMMEDIATE txn), the flip QUEUED->RUNNING and the
// lease stamp happen in one transaction — an orphan (RUNNING with no live lease,
// or a lease with no RUNNING job) is unrepresentable.
func (d *Dispatcher) tryClaim(runnerID string, lanes []string) (claimResult, *wire.Error) {
	var result claimResult
	err := d.store.writeTx(func(tx *sql.Tx) error {
		now := d.now()

		q, err := runnerQuarantined(tx, runnerID)
		if err != nil {
			return err
		}
		if q {
			result.outcome = claimQuarantined
			return nil
		}
		draining, err := runnerDraining(tx, runnerID)
		if err != nil {
			return err
		}
		if draining {
			result.outcome = claimDrained
			return nil
		}

		// Filter lanes: drop those in PERSISTING backpressure or at concurrency cap.
		var open []string
		anyBackpressure := false
		for _, lane := range lanes {
			lc := d.cfg.Lane(lane)
			if lc.PersistingWatermark > 0 {
				pc, err := laneCount(tx, lane, "PERSISTING")
				if err != nil {
					return err
				}
				if pc > lc.PersistingWatermark {
					anyBackpressure = true
					continue
				}
			}
			if lc.Concurrency > 0 {
				rc, err := laneCount(tx, lane, "RUNNING")
				if err != nil {
					return err
				}
				if rc >= lc.Concurrency {
					continue // lane full; not backpressure, just busy
				}
			}
			open = append(open, lane)
		}
		if len(open) == 0 {
			if anyBackpressure {
				result.outcome = claimBackpressure
				result.retryAfterS = 2
			} else {
				result.outcome = claimNoWork
			}
			return nil
		}

		// Round-robin across the open lanes so a deep backlog in one lane can't freeze
		// another: a single runner serves one job at a time, and taking the globally
		// oldest job let an older transcribe backlog starve embed for 36h (2026-07). Rotate
		// the starting lane each claim; within a lane, oldest-runnable still wins.
		numLanes := len(open)
		start := int(d.claimSeq.Add(1) % uint64(numLanes))
		var job Job
		var ok bool
		for i := 0; i < numLanes; i++ {
			job, ok, err = selectClaimableInLane(tx, open[(start+i)%numLanes], now)
			if err != nil {
				return err
			}
			if ok {
				break
			}
		}
		if !ok {
			result.outcome = claimNoWork
			return nil
		}

		// Rate cap: only consume quota once we know we have work to grant.
		if !d.rl.allow(runnerID, now) {
			result.outcome = claimRateLimited
			result.retryAfterS = 5
			return nil
		}

		leaseID := d.ids.LeaseID(now)
		deadlineTS := now + int64(d.cfg.LeaseTTLS)*1000
		res, err := tx.Exec(
			`UPDATE jobs SET state='RUNNING', lease_id=?, lease_deadline_ts=?, lease_runner_id=?, updated_ts=?
			 WHERE job_id=? AND state='QUEUED'`,
			leaseID, deadlineTS, runnerID, now, job.JobID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			// Should not happen under single-writer serialization; treat as no work.
			result.outcome = claimNoWork
			return nil
		}
		if err := insertAttempt(tx, job.JobID, job.Attempt, runnerID, leaseID, "claimed", "", "", now, 0); err != nil {
			return err
		}
		if err := touchRunner(tx, runnerID, now); err != nil {
			return err
		}

		gj := wire.GrantJob{
			JobID:             job.JobID,
			JobKey:            job.JobKey,
			Lane:              job.Lane,
			InvocationAddress: artifact.Address(job.InvocationAddress),
			Attempt:           job.Attempt,
			ExpectedWallS:     job.Policy.ExpectedWallS, // sizes the runner's per-job budget
		}
		if job.BatchScale != "" {
			gj.Hints = &wire.GrantHints{BatchScale: job.BatchScale}
		}
		result.outcome = claimGranted
		result.grant = wire.Grant{
			Job: gj,
			Lease: wire.LeaseGrant{
				LeaseID:    leaseID,
				TTLS:       d.cfg.LeaseTTLS,
				DeadlineTS: deadlineTS,
			},
		}
		return nil
	})
	if err != nil {
		return claimResult{}, &wire.Error{Code: wire.CodeInternal, Message: "lease: " + err.Error()}
	}
	return result, nil
}

// selectClaimableInLane returns the oldest runnable QUEUED job in ONE lane:
// next_attempt_at in the past, ordered by priority then age. The caller rotates over the
// open lanes for cross-lane fairness (see tryClaim), so this stays a single-lane query.
func selectClaimableInLane(tx *sql.Tx, lane string, now int64) (Job, bool, error) {
	query := `SELECT ` + jobColumns + ` FROM jobs
		WHERE state='QUEUED' AND lane=? AND next_attempt_at<=?
		ORDER BY priority ASC, created_ts ASC LIMIT 1`
	row := tx.QueryRow(query, lane, now)
	job, err := scanJob(row)
	if err == sql.ErrNoRows {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, err
	}
	return job, true, nil
}

// laneCount counts jobs in a lane in a given state.
func laneCount(tx *sql.Tx, lane, state string) (int, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM jobs WHERE lane=? AND state=?`, lane, state).Scan(&n)
	return n, err
}

// runnerQuarantined reports whether the runner is quarantined.
func runnerQuarantined(tx *sql.Tx, runnerID string) (bool, error) {
	var q int
	err := tx.QueryRow(`SELECT quarantined FROM runners WHERE runner_id=?`, runnerID).Scan(&q)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return q != 0, nil
}

// touchRunner updates last_seen for a runner (no-op if the row is absent; hello
// creates it).
func touchRunner(tx *sql.Tx, runnerID string, now int64) error {
	_, err := tx.Exec(`UPDATE runners SET last_seen_ts=? WHERE runner_id=?`, now, runnerID)
	return err
}

func intptr(v int) *int { return &v }
