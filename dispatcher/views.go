package dispatcher

import (
	"database/sql"
	"encoding/json"
	"github.com/falahat/dispatch-service/internal/wire"
	"strings"
)

// JobsFilter narrows a jobs query.
type JobsFilter struct {
	State        string
	Lane         string
	JobKeyPrefix string
	Limit        int
	Offset       int
}

// Jobs returns a filtered, paged view of jobs, newest first.
func (d *Dispatcher) Jobs(f JobsFilter) (wire.JobsResult, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	var where []string
	var args []any
	if f.State != "" {
		where = append(where, "state=?")
		args = append(args, f.State)
	}
	if f.Lane != "" {
		where = append(where, "lane=?")
		args = append(args, f.Lane)
	}
	if f.JobKeyPrefix != "" {
		where = append(where, `job_key LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(f.JobKeyPrefix)+"%")
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}
	// Fetch one extra row to decide whether there's a next page.
	args = append(args, f.Limit+1, f.Offset)
	rows, err := d.store.db.Query(
		`SELECT `+jobColumns+` FROM jobs `+clause+` ORDER BY created_ts DESC, job_id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return wire.JobsResult{}, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return wire.JobsResult{}, err
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return wire.JobsResult{}, err
	}
	rows.Close()
	out := wire.JobsResult{Jobs: []wire.JobView{}}
	if len(jobs) > f.Limit {
		jobs = jobs[:f.Limit]
		next := f.Offset + f.Limit
		out.NextPage = &next
	}
	for _, job := range jobs {
		view, err := d.jobView(job)
		if err != nil {
			return wire.JobsResult{}, err
		}
		out.Jobs = append(out.Jobs, view)
	}
	return out, nil
}

func (d *Dispatcher) jobView(j Job) (wire.JobView, error) {
	view := wire.JobView{JobID: j.JobID, JobKey: j.JobKey, Lane: j.Lane, State: j.State,
		Attempt: j.Attempt, ReleaseCount: j.ReleaseCount, InvocationAddress: j.InvocationAddress,
		NextAttemptAt: j.NextAttemptAt, CostUSD: j.CostCents.String(), Reason: j.Reason,
		CreatedTS: j.CreatedTS, UpdatedTS: j.UpdatedTS, RunnerID: j.LeaseRunnerID,
		CancelRequested: j.CancelRequested, ActionResult: json.RawMessage(j.ResultJSON)}
	var progress string
	err := d.store.db.QueryRow(`SELECT payload FROM job_progress WHERE job_id=? AND attempt=?`, j.JobID, j.Attempt).Scan(&progress)
	if err != nil && err != sql.ErrNoRows {
		return view, err
	}
	if err == nil {
		view.Progress = json.RawMessage(progress)
	}
	view.Timeline, err = d.timeline(j.JobID)
	return view, err
}

func (d *Dispatcher) timeline(jobID string) ([]wire.AttemptView, error) {
	rows, err := d.store.db.Query(
		`SELECT attempt, runner_id, lease_id, outcome, error_class, reason, COALESCE(ended_ts, started_ts, 0)
		 FROM attempts WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.AttemptView
	for rows.Next() {
		var av wire.AttemptView
		var runner, lease, class, reason sql.NullString
		if err := rows.Scan(&av.Attempt, &runner, &lease, &av.Outcome, &class, &reason, &av.TS); err != nil {
			return nil, err
		}
		av.RunnerID, av.LeaseID, av.ErrorClass, av.Reason = runner.String, lease.String, class.String, reason.String
		out = append(out, av)
	}
	return out, rows.Err()
}

// Fleet returns per-runner health.
func (d *Dispatcher) Fleet() ([]wire.RunnerView, error) {
	rows, err := d.store.db.Query(
		`SELECT runner_id, node, version, lanes, capacity, gpu, vram_free_mb, last_seen_ts,
			quarantined, quarantine_reason, draining, corroborated_failures FROM runners ORDER BY runner_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.RunnerView
	for rows.Next() {
		var rv wire.RunnerView
		var node, version, lanesJSON, gpu, qreason sql.NullString
		var capacity, vram sql.NullInt64
		var quarantined, draining int
		if err := rows.Scan(&rv.RunnerID, &node, &version, &lanesJSON, &capacity, &gpu, &vram,
			&rv.LastSeenTS, &quarantined, &qreason, &draining, &rv.CorroboratedFailures); err != nil {
			return nil, err
		}
		rv.Node, rv.Version, rv.GPU, rv.QuarantineReason = node.String, version.String, gpu.String, qreason.String
		rv.Capacity, rv.VRAMFreeMB = int(capacity.Int64), int(vram.Int64)
		rv.Quarantined, rv.Draining = quarantined != 0, draining != 0
		if lanesJSON.String != "" {
			_ = json.Unmarshal([]byte(lanesJSON.String), &rv.Lanes)
		}
		out = append(out, rv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Running-job counts per runner.
	for i := range out {
		var n int
		if err := d.store.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE state='RUNNING' AND lease_runner_id=?`, out[i].RunnerID).Scan(&n); err != nil {
			return nil, err
		}
		out[i].RunningJobs = n
	}
	return out, nil
}

// Budget returns the cost gate snapshot.
func (d *Dispatcher) Budget() (wire.BudgetView, error) {
	var cap, reserved, spent int64
	if err := d.store.db.QueryRow(`SELECT cap_cents, reserved_cents, spent_cents FROM budget WHERE id=1`).Scan(&cap, &reserved, &spent); err != nil {
		return wire.BudgetView{}, err
	}
	out := wire.BudgetView{CapUSD: Money(cap).String(), ReservedUSD: Money(reserved).String(), SpentUSD: Money(spent).String()}
	rows, err := d.store.db.Query(`SELECT job_id, job_key, state, cost_cents FROM jobs WHERE cost_cents > 0 ORDER BY created_ts DESC LIMIT 200`)
	if err != nil {
		return wire.BudgetView{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var it wire.BudgetLedgerItem
		var cents int64
		if err := rows.Scan(&it.JobID, &it.JobKey, &it.State, &cents); err != nil {
			return wire.BudgetView{}, err
		}
		it.CostUSD = Money(cents).String()
		out.Ledger = append(out.Ledger, it)
	}
	return out, rows.Err()
}

// SetRunnerDraining flips a runner's drain flag (admin, via dispatchctl).
func (d *Dispatcher) SetRunnerDraining(runnerID string, draining bool) error {
	v := 0
	if draining {
		v = 1
	}
	_, err := d.store.db.Exec(`UPDATE runners SET draining=? WHERE runner_id=?`, v, runnerID)
	return err
}

// ClearQuarantine lifts a runner's quarantine (admin, after remediation).
func (d *Dispatcher) ClearQuarantine(runnerID string) error {
	_, err := d.store.db.Exec(`UPDATE runners SET quarantined=0, quarantine_reason=NULL, corroborated_failures=0 WHERE runner_id=?`, runnerID)
	return err
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}
