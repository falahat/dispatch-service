package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The view types below mirror the dispatcher's read projections
// (dispatcher/views.go, dispatcher/sweep.go). They are duplicated here rather
// than imported so dispatchctl depends only on the wire framing and speaks the
// app surface as an ordinary client would.

type attemptView struct {
	Attempt    int    `json:"attempt"`
	RunnerID   string `json:"runner_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	Outcome    string `json:"outcome"`
	ErrorClass string `json:"error_class,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TS         int64  `json:"ts"`
}

type jobView struct {
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
	Timeline          []attemptView `json:"timeline"`
}

type jobsResult struct {
	Jobs     []jobView `json:"jobs"`
	NextPage *int      `json:"next_page,omitempty"`
}

type runnerView struct {
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

type fleetResult struct {
	Runners []runnerView `json:"runners"`
}

type budgetLedgerItem struct {
	JobID   string `json:"job_id"`
	JobKey  string `json:"job_key"`
	State   string `json:"state"`
	CostUSD string `json:"cost_usd"`
}

type budgetView struct {
	CapUSD      string             `json:"cap_usd"`
	ReservedUSD string             `json:"reserved_usd"`
	SpentUSD    string             `json:"spent_usd"`
	Ledger      []budgetLedgerItem `json:"ledger"`
}

type sweepResult struct {
	Recovered    int `json:"recovered"`
	Expired      int `json:"expired"`
	GCCandidates int `json:"gc_candidates"`
}

type enqueueResultItem struct {
	JobKey  string `json:"job_key"`
	JobID   string `json:"job_id"`
	Created bool   `json:"created"`
}

type enqueueResult struct {
	Results []enqueueResultItem `json:"results"`
}

// --- table rendering ---

// table renders rows as space-aligned columns under a header, matching each
// column's width to its widest cell. A trailing empty line separates it from
// following output.
func table(w *strings.Builder, header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	writeRow(w, header, widths)
	for _, r := range rows {
		writeRow(w, r, widths)
	}
}

func writeRow(w *strings.Builder, cells []string, widths []int) {
	for i, cell := range cells {
		if i > 0 {
			w.WriteString("  ")
		}
		w.WriteString(cell)
		// Pad all but the last column so ragged right edges don't accumulate
		// trailing whitespace.
		if i < len(cells)-1 {
			w.WriteString(strings.Repeat(" ", widths[i]-len(cell)))
		}
	}
	w.WriteByte('\n')
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// renderJobs prints the jobs table used by `jobs`.
func renderJobs(res jobsResult) string {
	var w strings.Builder
	if len(res.Jobs) == 0 {
		w.WriteString("no jobs\n")
		return w.String()
	}
	header := []string{"JOB_ID", "STATE", "LANE", "ATTEMPT", "JOB_KEY", "REASON"}
	rows := make([][]string, 0, len(res.Jobs))
	for _, j := range res.Jobs {
		rows = append(rows, []string{
			j.JobID, j.State, j.Lane, strconv.Itoa(j.Attempt), j.JobKey, dash(j.Reason),
		})
	}
	table(&w, header, rows)
	if res.NextPage != nil {
		fmt.Fprintf(&w, "\n(more: --page %d)\n", *res.NextPage)
	}
	return w.String()
}

// renderJobDetail prints one job's full detail plus its attempt timeline, the
// view backing `job` and `trace`.
func renderJobDetail(j jobView) string {
	var w strings.Builder
	fmt.Fprintf(&w, "job_id      %s\n", j.JobID)
	fmt.Fprintf(&w, "job_key     %s\n", j.JobKey)
	fmt.Fprintf(&w, "lane        %s\n", j.Lane)
	fmt.Fprintf(&w, "state       %s\n", j.State)
	fmt.Fprintf(&w, "attempt     %d\n", j.Attempt)
	fmt.Fprintf(&w, "releases    %d\n", j.ReleaseCount)
	fmt.Fprintf(&w, "invocation  %s\n", j.InvocationAddress)
	fmt.Fprintf(&w, "cost_usd    %s\n", j.CostUSD)
	if j.Reason != "" {
		fmt.Fprintf(&w, "reason      %s\n", j.Reason)
	}
	fmt.Fprintf(&w, "created     %s\n", ts(j.CreatedTS))
	fmt.Fprintf(&w, "updated     %s\n", ts(j.UpdatedTS))
	if j.NextAttemptAt > 0 {
		fmt.Fprintf(&w, "next_attempt %s\n", ts(j.NextAttemptAt))
	}
	w.WriteString("\ntimeline\n")
	w.WriteString(renderTimeline(j))
	return w.String()
}

// renderTimeline renders a job's attempt/release chronology as readable prose.
// This is the human console's headline: each attempt as a claimed/failed/
// requeued line, ending at the terminal state.
func renderTimeline(j jobView) string {
	var w strings.Builder
	if len(j.Timeline) == 0 {
		w.WriteString("  (no events)\n")
		return w.String()
	}
	for _, a := range j.Timeline {
		fmt.Fprintf(&w, "  %s  %s\n", ts(a.TS), describeAttempt(a))
	}
	return w.String()
}

// describeAttempt turns one timeline row into a human phrase. Outcomes come
// from the dispatcher's attempts log (enqueue, claim, complete, fail,
// release, lease_expired, cancel, ack, approve, reject, ...).
func describeAttempt(a attemptView) string {
	who := ""
	if a.RunnerID != "" {
		who = " by " + a.RunnerID
	}
	detail := ""
	switch {
	case a.ErrorClass != "" && a.Reason != "":
		detail = fmt.Sprintf(" (%s: %s)", a.ErrorClass, a.Reason)
	case a.ErrorClass != "":
		detail = fmt.Sprintf(" (%s)", a.ErrorClass)
	case a.Reason != "":
		detail = fmt.Sprintf(" (%s)", a.Reason)
	}
	switch a.Outcome {
	case "enqueue":
		return "enqueued" + detail
	case "claimed":
		return fmt.Sprintf("attempt %d: claimed%s", a.Attempt, who) + detail
	case "complete":
		return fmt.Sprintf("attempt %d: completed%s -> PERSISTING", a.Attempt, who) + detail
	case "fail":
		return fmt.Sprintf("attempt %d: failed%s", a.Attempt, who) + detail
	case "release":
		return fmt.Sprintf("attempt %d: released%s -> requeued", a.Attempt, who) + detail
	case "lease_expired":
		return fmt.Sprintf("attempt %d: lease expired%s -> requeued", a.Attempt, who) + detail
	case "cancel":
		return "cancelled" + detail
	case "ack":
		return "ack" + detail
	default:
		// Unknown outcome: show it verbatim rather than guessing.
		return fmt.Sprintf("attempt %d: %s%s", a.Attempt, a.Outcome, detail)
	}
}

// renderFleet prints the fleet table used by `fleet`.
func renderFleet(res fleetResult) string {
	var w strings.Builder
	if len(res.Runners) == 0 {
		w.WriteString("no runners\n")
		return w.String()
	}
	header := []string{"RUNNER_ID", "NODE", "LANES", "CAP", "QUAR", "DRAIN", "RUNNING", "LAST_SEEN"}
	rows := make([][]string, 0, len(res.Runners))
	for _, r := range res.Runners {
		rows = append(rows, []string{
			r.RunnerID,
			dash(r.Node),
			dash(strings.Join(r.Lanes, ",")),
			strconv.Itoa(r.Capacity),
			yesno(r.Quarantined),
			yesno(r.Draining),
			strconv.Itoa(r.RunningJobs),
			ts(r.LastSeenTS),
		})
	}
	table(&w, header, rows)
	return w.String()
}

// renderBudget prints the cost gate snapshot used by `budget`.
func renderBudget(b budgetView) string {
	var w strings.Builder
	fmt.Fprintf(&w, "cap       $%s\n", b.CapUSD)
	fmt.Fprintf(&w, "reserved  $%s\n", b.ReservedUSD)
	fmt.Fprintf(&w, "spent     $%s\n", b.SpentUSD)
	if len(b.Ledger) == 0 {
		w.WriteString("\nledger    (empty)\n")
		return w.String()
	}
	w.WriteString("\nledger\n")
	header := []string{"JOB_ID", "STATE", "COST_USD", "JOB_KEY"}
	rows := make([][]string, 0, len(b.Ledger))
	for _, it := range b.Ledger {
		rows = append(rows, []string{it.JobID, it.State, "$" + it.CostUSD, it.JobKey})
	}
	table(&w, header, rows)
	return w.String()
}

// renderSweep prints the sweep counters.
func renderSweep(s sweepResult) string {
	return fmt.Sprintf("recovered %d  expired %d  gc_candidates %d\n",
		s.Recovered, s.Expired, s.GCCandidates)
}

// renderEnqueue prints the result of a single-job enqueue.
func renderEnqueue(res enqueueResult) string {
	var w strings.Builder
	for _, it := range res.Results {
		verb := "exists"
		if it.Created {
			verb = "created"
		}
		fmt.Fprintf(&w, "%s  %s  (%s)\n", it.JobID, it.JobKey, verb)
	}
	return w.String()
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ts renders a server millisecond timestamp as a local, second-precision time.
// Zero (unset) renders as a dash.
func ts(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}
