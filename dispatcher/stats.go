package dispatcher

import (
	"database/sql"
	"github.com/falahat/dispatch-service/internal/wire"
)

// Drain-health snapshot: the counts that answer "is the queue draining?" in one
// read-only pass. This is the verb behind `dispatchctl stats`, the app's
// exported drain gauges, and the plane-aware stall alert. Activity is not
// progress — during the 2026-07 drain-collapse the GPU was busy and the logs
// scrolled while ~36k jobs failed; these counts are the truth that was hidden.

// statsWindowDefaultS is the trailing window attempt outcomes are counted over
// when the request does not name one.
const statsWindowDefaultS = 900

// statsWindowMaxS caps the requested window (the attempts scan is unindexed by
// time; a week is more than any live-health question needs).
const statsWindowMaxS = 7 * 86_400

// statsFailureLimit bounds the grouped recent-failure rows (top offenders only;
// the full timeline stays in `jobs`/`trace`).
const statsFailureLimit = 10

// StatsRequest narrows a stats query. WindowS <= 0 means the default window.
type StatsRequest struct {
	WindowS int `json:"window_s,omitempty"`
}

// JobCount is one (lane, state) cell of the queue snapshot.
type JobCount = wire.JobCount

// AttemptCount is one (lane, outcome) cell of the trailing window: outcome is
// the attempts-log verb (enqueue | complete | fail | release | lease_expired |
// ack | cancel). In-flight `claimed` rows carry no ended_ts and are excluded —
// this is the settled-event rate, not a busyness meter.
type AttemptCount = wire.AttemptCount

// FailureCount is one grouped recent-failure row — the "why is it failing"
// column of the drain view.
type FailureCount = wire.FailureCount

// StatsView is the whole drain-health snapshot.
type StatsView = wire.StatsView

// Stats builds the drain-health snapshot: job counts by (lane, state), attempt
// outcomes over the trailing window, the grouped top failure reasons, and the
// age of the oldest QUEUED job (0 when the queue is empty). Read-only.
func (d *Dispatcher) Stats(req StatsRequest) (StatsView, error) {
	windowS := req.WindowS
	if windowS <= 0 {
		windowS = statsWindowDefaultS
	}
	if windowS > statsWindowMaxS {
		windowS = statsWindowMaxS
	}
	now := d.now()
	out := StatsView{ServerTS: now, WindowS: windowS}
	cutoff := now - int64(windowS)*1000

	if err := d.statsJobs(&out); err != nil {
		return StatsView{}, err
	}
	if err := d.statsAttempts(&out, cutoff); err != nil {
		return StatsView{}, err
	}
	if err := d.statsFailures(&out, cutoff); err != nil {
		return StatsView{}, err
	}

	// Oldest QUEUED age: how long the head of the queue has been waiting since
	// creation — a growing age with a live runner is the stall signature.
	var oldest int64
	if err := d.store.db.QueryRow(
		`SELECT COALESCE(MIN(created_ts), 0) FROM jobs WHERE state='QUEUED'`).Scan(&oldest); err != nil {
		return StatsView{}, err
	}
	if oldest > 0 {
		out.OldestQueuedAgeS = (now - oldest) / 1000
	}
	return out, nil
}

// statsJobs fills the (lane, state) queue snapshot.
func (d *Dispatcher) statsJobs(out *StatsView) error {
	rows, err := d.store.db.Query(
		`SELECT lane, state, COUNT(*) FROM jobs GROUP BY lane, state ORDER BY lane, state`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var jc JobCount
		if err := rows.Scan(&jc.Lane, &jc.State, &jc.Count); err != nil {
			return err
		}
		out.Jobs = append(out.Jobs, jc)
	}
	return rows.Err()
}

// statsAttempts fills the (lane, outcome) counts of attempts settled within the
// window. Settled outcomes carry ended_ts; in-flight `claimed` rows do not, so
// the time filter naturally excludes them. Lane comes from the job row; a job
// pruned by retention takes its attempts with it, and the retention window
// (days) dwarfs any stats window, so the join cannot undercount live health.
func (d *Dispatcher) statsAttempts(out *StatsView, cutoff int64) error {
	rows, err := d.store.db.Query(
		`SELECT j.lane, a.outcome, COUNT(*) FROM attempts a
		 JOIN jobs j ON j.job_id = a.job_id
		 WHERE a.ended_ts >= ? GROUP BY j.lane, a.outcome ORDER BY j.lane, a.outcome`, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ac AttemptCount
		if err := rows.Scan(&ac.Lane, &ac.Outcome, &ac.Count); err != nil {
			return err
		}
		out.Attempts = append(out.Attempts, ac)
	}
	return rows.Err()
}

// statsFailures fills the grouped recent-failure rows, worst offenders first.
func (d *Dispatcher) statsFailures(out *StatsView, cutoff int64) error {
	rows, err := d.store.db.Query(
		`SELECT j.lane, a.error_class, a.reason, COUNT(*) AS n FROM attempts a
		 JOIN jobs j ON j.job_id = a.job_id
		 WHERE a.outcome = 'fail' AND a.ended_ts >= ?
		 GROUP BY j.lane, a.error_class, a.reason
		 ORDER BY n DESC, j.lane LIMIT ?`, cutoff, statsFailureLimit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var fc FailureCount
		var class, reason sql.NullString
		if err := rows.Scan(&fc.Lane, &class, &reason, &fc.Count); err != nil {
			return err
		}
		fc.ErrorClass, fc.Reason = class.String, reason.String
		out.RecentFailures = append(out.RecentFailures, fc)
	}
	return rows.Err()
}
