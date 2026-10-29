package wire

import "encoding/json"

// App read projections are shared contract types, without dispatcher behavior.
type AttemptView struct {
	Attempt    int    `json:"attempt"`
	RunnerID   string `json:"runner_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	Outcome    string `json:"outcome"`
	ErrorClass string `json:"error_class,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TS         int64  `json:"ts"`
}

type JobView struct {
	JobID             string          `json:"job_id"`
	JobKey            string          `json:"job_key"`
	Lane              string          `json:"lane"`
	State             string          `json:"state"`
	Attempt           int             `json:"attempt"`
	ReleaseCount      int             `json:"release_count"`
	InvocationAddress string          `json:"invocation_address"`
	NextAttemptAt     int64           `json:"next_attempt_at"`
	CostUSD           string          `json:"cost_usd"`
	Reason            string          `json:"reason,omitempty"`
	CreatedTS         int64           `json:"created_ts"`
	UpdatedTS         int64           `json:"updated_ts"`
	Timeline          []AttemptView   `json:"timeline"`
	RunnerID          string          `json:"runner_id,omitempty"`
	CancelRequested   bool            `json:"cancel_requested"`
	ActionResult      json.RawMessage `json:"action_result,omitempty"`
	Progress          json.RawMessage `json:"progress,omitempty"`
}

type JobsResult struct {
	Jobs     []JobView `json:"jobs"`
	NextPage *int      `json:"next_page,omitempty"`
}

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

type BudgetLedgerItem struct {
	JobID   string `json:"job_id"`
	JobKey  string `json:"job_key"`
	State   string `json:"state"`
	CostUSD string `json:"cost_usd"`
}

type BudgetView struct {
	CapUSD      string             `json:"cap_usd"`
	ReservedUSD string             `json:"reserved_usd"`
	SpentUSD    string             `json:"spent_usd"`
	Ledger      []BudgetLedgerItem `json:"ledger"`
}

type JobCount struct {
	Lane  string `json:"lane"`
	State string `json:"state"`
	Count int    `json:"count"`
}

type AttemptCount struct {
	Lane    string `json:"lane"`
	Outcome string `json:"outcome"`
	Count   int    `json:"count"`
}

type FailureCount struct {
	Lane       string `json:"lane"`
	ErrorClass string `json:"error_class,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Count      int    `json:"count"`
}

type StatsView struct {
	ServerTS         int64          `json:"server_ts"`
	WindowS          int            `json:"window_s"`
	Jobs             []JobCount     `json:"jobs"`
	Attempts         []AttemptCount `json:"attempts"`
	RecentFailures   []FailureCount `json:"recent_failures,omitempty"`
	OldestQueuedAgeS int64          `json:"oldest_queued_age_s"`
}

type SweepResult struct {
	Recovered    int `json:"recovered"`     // expired leases requeued (presumed crash)
	Expired      int `json:"expired"`       // expired leases that hit max_attempts -> FAILED
	GCCandidates int `json:"gc_candidates"` // terminal jobs whose CAS pins are released
	Pruned       int `json:"pruned"`        // terminal jobs deleted by the retention window (0 = no TTL)
}

type FleetResult struct {
	Runners []RunnerView `json:"runners"`
}
