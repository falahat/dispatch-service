// Command dispatchctl is the admin CLI over the dispatcher's app surface. It
// speaks the length-prefixed JSON wire protocol (internal/wire) as an ordinary
// client and exposes read views (jobs, job, fleet, budget, trace) and admin
// verbs (cancel, approve, reject, ack, sweep, enqueue). The app surface needs
// no hello/auth: filesystem permissions on the Unix socket are the access
// control (loopback TCP where AF_UNIX is absent).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

const usage = `dispatchctl - admin CLI for the dispatcher app surface

usage: dispatchctl -addr <unix:/path|host:port> <command> [args]

commands:
  jobs   [--state S] [--lane L] [--prefix P] [--page N]   list jobs
  job    <job_id>                                         one job's full detail + timeline
  trace  <job_id>                                         render a job's attempt timeline
  fleet                                                   list runners
  budget                                                  cost gate snapshot + ledger
  cancel <job_id> [--reason R]                            cancel a non-terminal job
  approve <job_id> --author A [--reason R]                approve a priced job
  reject  <job_id> --author A [--reason R]                reject a priced job
  ack    <job_id> persisted|rejected [--reason R]         ack a PERSISTING job
  sweep                                                   run the timer pass now
  enqueue --key K --lane L --inv <sha256:...> [--cost N.CC]   enqueue one job
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dispatchctl: "+err.Error())
		os.Exit(1)
	}
}

// run parses the global -addr flag and the subcommand, then dispatches. It
// returns an error (printed to stderr with a non-zero exit) on any failure,
// including an `error` reply from the dispatcher.
func run(args []string) error {
	global := flag.NewFlagSet("dispatchctl", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	addr := global.String("addr", "", "app-surface address: unix:/path or host:port")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}
	if *addr == "" {
		return errors.New("-addr is required")
	}
	cmd, cmdArgs := rest[0], rest[1:]

	handler, ok := commands[cmd]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}

	c, err := dial(*addr)
	if err != nil {
		return err
	}
	defer c.close()
	return handler(c, cmdArgs)
}

// commands maps a subcommand name to its handler.
var commands = map[string]func(*client, []string) error{
	"jobs":    cmdJobs,
	"job":     cmdJob,
	"trace":   cmdTrace,
	"fleet":   cmdFleet,
	"budget":  cmdBudget,
	"cancel":  cmdCancel,
	"approve": cmdApprove,
	"reject":  cmdReject,
	"ack":     cmdAck,
	"sweep":   cmdSweep,
	"enqueue": cmdEnqueue,
}

// jobsFilterWire matches the dispatcher's `jobs` request body:
// {"filter":{"state","lane","job_key_prefix"},"page":<int>}.
type jobsFilterWire struct {
	State        string `json:"state,omitempty"`
	Lane         string `json:"lane,omitempty"`
	JobKeyPrefix string `json:"job_key_prefix,omitempty"`
}

type jobsRequest struct {
	Filter *jobsFilterWire `json:"filter,omitempty"`
	Page   *int            `json:"page,omitempty"`
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func cmdJobs(c *client, args []string) error {
	fs := newFlagSet("jobs")
	state := fs.String("state", "", "filter by state")
	lane := fs.String("lane", "", "filter by lane")
	prefix := fs.String("prefix", "", "filter by job_key prefix")
	page := fs.Int("page", 0, "page offset")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req := jobsRequest{}
	if *state != "" || *lane != "" || *prefix != "" {
		req.Filter = &jobsFilterWire{State: *state, Lane: *lane, JobKeyPrefix: *prefix}
	}
	if *page != 0 {
		req.Page = page
	}
	res, err := fetchJobs(c, req)
	if err != nil {
		return err
	}
	fmt.Print(renderJobs(res))
	return nil
}

func cmdJob(c *client, args []string) error {
	fs := newFlagSet("job")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("job: exactly one <job_id> required")
	}
	j, err := findJob(c, fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Print(renderJobDetail(j))
	return nil
}

func cmdTrace(c *client, args []string) error {
	fs := newFlagSet("trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("trace: exactly one <job_id> required")
	}
	j, err := findJob(c, fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s  [%s]\n\n", j.JobID, j.JobKey, j.State)
	fmt.Print(renderTimeline(j))
	return nil
}

func cmdFleet(c *client, args []string) error {
	fs := newFlagSet("fleet")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := c.call(wire.TypeFleet, struct{}{})
	if err != nil {
		return err
	}
	res, err := wire.DecodeBody[fleetResult](env)
	if err != nil {
		return err
	}
	fmt.Print(renderFleet(res))
	return nil
}

func cmdBudget(c *client, args []string) error {
	fs := newFlagSet("budget")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := c.call(wire.TypeBudget, struct{}{})
	if err != nil {
		return err
	}
	b, err := wire.DecodeBody[budgetView](env)
	if err != nil {
		return err
	}
	fmt.Print(renderBudget(b))
	return nil
}

func cmdCancel(c *client, args []string) error {
	fs := newFlagSet("cancel")
	reason := fs.String("reason", "", "cancellation reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("cancel: exactly one <job_id> required")
	}
	env, err := c.call(wire.TypeCancel, wire.Cancel{JobID: fs.Arg(0), Reason: *reason})
	if err != nil {
		return err
	}
	return expectOK(env, "cancelled "+fs.Arg(0))
}

func cmdApprove(c *client, args []string) error { return approval(c, args, wire.TypeApprove) }
func cmdReject(c *client, args []string) error  { return approval(c, args, wire.TypeReject) }

func approval(c *client, args []string, typ string) error {
	fs := newFlagSet(typ)
	author := fs.String("author", "", "approving author (required)")
	reason := fs.String("reason", "", "reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%s: exactly one <job_id> required", typ)
	}
	if *author == "" {
		return fmt.Errorf("%s: --author is required", typ)
	}
	env, err := c.call(typ, wire.Approval{JobID: fs.Arg(0), Author: *author, Reason: *reason})
	if err != nil {
		return err
	}
	return expectOK(env, typ+"d "+fs.Arg(0))
}

func cmdAck(c *client, args []string) error {
	fs := newFlagSet("ack")
	reason := fs.String("reason", "", "reason (for rejected)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("ack: <job_id> persisted|rejected required")
	}
	jobID := fs.Arg(0)
	var disp wire.Disposition
	switch fs.Arg(1) {
	case "persisted":
		disp = wire.DispositionPersisted
	case "rejected":
		disp = wire.DispositionRejected
	default:
		return fmt.Errorf("ack: disposition must be persisted|rejected, got %q", fs.Arg(1))
	}
	env, err := c.call(wire.TypeAck, wire.Ack{JobID: jobID, Disposition: disp, Reason: *reason})
	if err != nil {
		return err
	}
	return expectOK(env, "acked "+jobID+" "+string(disp))
}

func cmdSweep(c *client, args []string) error {
	fs := newFlagSet("sweep")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := c.call(wire.TypeSweep, struct{}{})
	if err != nil {
		return err
	}
	s, err := wire.DecodeBody[sweepResult](env)
	if err != nil {
		return err
	}
	fmt.Print(renderSweep(s))
	return nil
}

func cmdEnqueue(c *client, args []string) error {
	fs := newFlagSet("enqueue")
	key := fs.String("key", "", "job_key (required)")
	lane := fs.String("lane", "", "lane (required)")
	inv := fs.String("inv", "", "invocation address sha256:... (required)")
	cost := fs.String("cost", "", "cost estimate USD as N.CC (priced jobs park in AWAITING_APPROVAL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *lane == "" || *inv == "" {
		return errors.New("enqueue: --key, --lane and --inv are all required")
	}
	env, err := c.call(wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{{
		JobKey:            *key,
		Lane:              *lane,
		InvocationAddress: artifact.Address(*inv),
		CostEstimateUSD:   *cost,
	}}})
	if err != nil {
		return err
	}
	res, err := wire.DecodeBody[enqueueResult](env)
	if err != nil {
		return err
	}
	fmt.Print(renderEnqueue(res))
	return nil
}

// --- shared helpers ---

// fetchJobs sends a jobs request and decodes the jobs_result reply.
func fetchJobs(c *client, req jobsRequest) (jobsResult, error) {
	env, err := c.call(wire.TypeJobs, req)
	if err != nil {
		return jobsResult{}, err
	}
	return wire.DecodeBody[jobsResult](env)
}

// findJob locates a single job by its exact job_id. The app surface has no
// by-id lookup, so this pages the read view (newest first) until it finds a
// matching row. Job ids are ULIDs (time-sortable), so the target is usually on
// an early page.
func findJob(c *client, jobID string) (jobView, error) {
	page := 0
	for {
		req := jobsRequest{}
		if page != 0 {
			p := page
			req.Page = &p
		}
		res, err := fetchJobs(c, req)
		if err != nil {
			return jobView{}, err
		}
		for _, j := range res.Jobs {
			if j.JobID == jobID {
				return j, nil
			}
		}
		if res.NextPage == nil {
			return jobView{}, fmt.Errorf("job %q not found", jobID)
		}
		page = *res.NextPage
	}
}

// expectOK asserts an "ok" reply and prints a success line. A non-ok, non-error
// reply is a protocol surprise worth surfacing.
func expectOK(env wire.Envelope, msg string) error {
	if env.Type != wire.TypeOK {
		return fmt.Errorf("unexpected reply type %q", env.Type)
	}
	fmt.Println(msg)
	return nil
}
