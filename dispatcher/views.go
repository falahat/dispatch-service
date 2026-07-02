package dispatcher

import (
	"database/sql"
	"encoding/json"
	"strings"
)

// AttemptView is one row of a job's attempt/release timeline.
type AttemptView struct {
	Attempt    int    `json:"attempt"`
	RunnerID   string `json:"runner_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	Outcome    string `json:"outcome"`
	ErrorClass string `json:"error_class,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TS         int64  `json:"ts"`
}

// JobView is the read projection of a job, including its full timeline (the
// dead-letter view is jobs{state: FAILED}).
type JobView struct {
	JobID             string        `json:"job_id"`
	JobKey            string        `json:"job_key"`
	Lane              string        `json:"lane"`
	State             string        `json:"state"`
	Attempt           int           `json:"attempt"`
	ReleaseCount      int           `json:"release_count"`
	InvocationAddress string        `json:"invocation_address"`
	NextAttemptAt     int64         `json:"next_attempt_at"`
	CostUSD           string        `json:"cost_usd"`
	Reason            string        `json:"reason,omitempty"`
	CreatedTS         int64         `json:"created_ts"`
	UpdatedTS         int64         `json:"updated_ts"`
	Timeline          []AttemptView `json:"timeline"`
}

// JobsFilter narrows a jobs query.
type JobsFilter struct {
	State        string
	Lane         string
	JobKeyPrefix string
	Limit        int
	Offset       int
}

// JobsResult is a page of jobs.
type JobsResult struct {
	Jobs     []JobView `json:"jobs"`
	NextPage *int      `json:"next_page,omitempty"`
}

// Jobs returns a filtered, paged view of jobs, newest first.
func (d *Dispatcher) Jobs(f JobsFilter) (JobsResult, error) {
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
		return JobsResult{}, err
	}
	defer rows.Close()
	var out JobsResult
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return JobsResult{}, err
		}
		out.Jobs = append(out.Jobs, JobView{
			JobID: j.JobID, JobKey: j.JobKey, Lane: j.Lane, State: j.State,
			Attempt: j.Attempt, ReleaseCount: j.ReleaseCount, InvocationAddress: j.InvocationAddress,
			NextAttemptAt: j.NextAttemptAt, CostUSD: j.CostCents.String(), Reason: j.Reason,
			CreatedTS: j.CreatedTS, UpdatedTS: j.UpdatedTS,
		})
	}
	if err := rows.Err(); err != nil {
		return JobsResult{}, err
	}
	if len(out.Jobs) > f.Limit {
		out.Jobs = out.Jobs[:f.Limit]
		next := f.Offset + f.Limit
		out.NextPage = &next
	}
	// Attach timelines.
	for i := range out.Jobs {
		tl, err := d.timeline(out.Jobs[i].JobID)
		if err != nil {
			return JobsResult{}, err
		}
		out.Jobs[i].Timeline = tl
	}
	return out, nil
}

func (d *Dispatcher) timeline(jobID string) ([]AttemptView, error) {
	rows, err := d.store.db.Query(
		`SELECT attempt, runner_id, lease_id, outcome, error_class, reason, COALESCE(ended_ts, started_ts, 0)
		 FROM attempts WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttemptView
	for rows.Next() {
		var av AttemptView
		var runner, lease, class, reason sql.NullString
		if err := rows.Scan(&av.Attempt, &runner, &lease, &av.Outcome, &class, &reason, &av.TS); err != nil {
			return nil, err
		}
		av.RunnerID, av.LeaseID, av.ErrorClass, av.Reason = runner.String, lease.String, class.String, reason.String
		out = append(out, av)
	}
	return out, rows.Err()
}

// RunnerView is a fleet snapshot row.
type RunnerView struct {
	RunnerID             string   `json:"runner_id"`
	Node                 string   `json:"node"`
	Version              string   `json:"version"`
	Lanes                []string `json:"lanes"`
	Capacity             int      `json:"capacity"`
	GPU                  string   `json:"gpu,omitempty"`
	VRAMFreeMB           int      `json:"vram_free_mb,omitempty"`
	LastSeenTS           int64    `json:"last_seen_ts"`
	Quarantined          bool     `json:"quarantined"`
	QuarantineReason     string   `json:"quarantine_reason,omitempty"`
	Draining             bool     `json:"draining"`
	CorroboratedFailures int      `json:"corroborated_failures"`
	RunningJobs          int      `json:"running_jobs"`
}

// Fleet returns per-runner health.
func (d *Dispatcher) Fleet() ([]RunnerView, error) {
	rows, err := d.store.db.Query(
		`SELECT runner_id, node, version, lanes, capacity, gpu, vram_free_mb, last_seen_ts,
			quarantined, quarantine_reason, draining, corroborated_failures FROM runners ORDER BY runner_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunnerView
	for rows.Next() {
		var rv RunnerView
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

// BudgetLedgerItem is one priced job's contribution.
type BudgetLedgerItem struct {
	JobID   string `json:"job_id"`
	JobKey  string `json:"job_key"`
	State   string `json:"state"`
	CostUSD string `json:"cost_usd"`
}

// BudgetView is the cost snapshot.
type BudgetView struct {
	CapUSD      string             `json:"cap_usd"`
	ReservedUSD string             `json:"reserved_usd"`
	SpentUSD    string             `json:"spent_usd"`
	Ledger      []BudgetLedgerItem `json:"ledger"`
}

// Budget returns the cost gate snapshot.
func (d *Dispatcher) Budget() (BudgetView, error) {
	var cap, reserved, spent int64
	if err := d.store.db.QueryRow(`SELECT cap_cents, reserved_cents, spent_cents FROM budget WHERE id=1`).Scan(&cap, &reserved, &spent); err != nil {
		return BudgetView{}, err
	}
	out := BudgetView{CapUSD: Money(cap).String(), ReservedUSD: Money(reserved).String(), SpentUSD: Money(spent).String()}
	rows, err := d.store.db.Query(`SELECT job_id, job_key, state, cost_cents FROM jobs WHERE cost_cents > 0 ORDER BY created_ts DESC LIMIT 200`)
	if err != nil {
		return BudgetView{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var it BudgetLedgerItem
		var cents int64
		if err := rows.Scan(&it.JobID, &it.JobKey, &it.State, &cents); err != nil {
			return BudgetView{}, err
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
