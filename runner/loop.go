package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

// Run drives the runner: boot readiness gate, then lease -> fetch -> invoke ->
// put -> complete, with a concurrent heartbeat/directive channel. It returns
// when ctx is cancelled or on drain.
func (r *Runner) Run(ctx context.Context) error {
	// Boot gate: the compute must be ready and serving the expected op before
	// this runner joins the fleet (INVOKE.md).
	if _, err := r.invoke.WaitReady(ctx, 60*time.Second); err != nil {
		return fmt.Errorf("runner: compute not ready: %w", err)
	}

	work, workOK, err := dialDispatcher(ctx, r.cfg.DispatcherAddr, r.ident(), r.wrapper)
	if err != nil {
		return err
	}
	defer work.close()

	hb, _, err := dialDispatcher(ctx, r.cfg.DispatcherAddr, r.ident(), r.wrapper)
	if err != nil {
		return err
	}
	defer hb.close()

	interval := workOK.HeartbeatIntervalS
	if interval <= 0 {
		interval = 15
	}
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go r.heartbeatLoop(hbCtx, hb, time.Duration(interval)*time.Second)

	r.log.Info("runner up", "node", r.cfg.Node, "lanes", r.cfg.Lanes)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if r.isDraining() {
			r.log.Info("draining; exiting")
			return nil
		}
		if wait := r.throttleWait(); wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			continue
		}

		grant, err := r.lease(ctx, work)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.log.Warn("lease error; reconnecting", "err", err)
			work.close()
			work, err = r.redial(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
				}
			}
			continue
		}
		if grant == nil {
			continue // empty long-poll; loop again
		}
		r.processJob(ctx, work, grant)
	}
}

func (r *Runner) redial(ctx context.Context) (*dispatcherConn, error) {
	dc, _, err := dialDispatcher(ctx, r.cfg.DispatcherAddr, r.ident(), r.wrapper)
	return dc, err
}

// lease long-polls for a job. A nil grant with nil error means "no work".
func (r *Runner) lease(ctx context.Context, dc *dispatcherConn) (*wire.Grant, error) {
	dc.setReadTimeout(time.Duration(r.cfg.LeaseWaitS+15) * time.Second)
	defer dc.setReadTimeout(0)
	env, err := dc.call(wire.TypeLease, wire.Lease{Lanes: r.cfg.Lanes, WaitS: r.cfg.LeaseWaitS})
	if err != nil {
		return nil, err
	}
	if e := asError(env); e != nil {
		return nil, e
	}
	switch env.Type {
	case wire.TypeGrant:
		g, err := wire.DecodeBody[wire.Grant](env)
		if err != nil {
			return nil, err
		}
		return &g, nil
	case wire.TypeEmpty:
		return nil, nil
	default:
		return nil, fmt.Errorf("lease: unexpected reply %s", env.Type)
	}
}

// jobBudgetMultiple scales a job's expected wall into its execution budget: the runner
// gives up on the compute only once a job runs this many times longer than the app
// expected, so ordinary variance (a slow disk, a cold model, a busy GPU) never trips it —
// only a genuinely wedged compute does.
const jobBudgetMultiple = 4

// jobBudgetFloor keeps a small or under-estimated expected wall from producing a
// dangerously tight budget (killing a legitimate job is the failure we most want to avoid).
const jobBudgetFloor = 2 * time.Minute

// jobBudget is how long a job may run before the runner treats its compute as wedged and
// gives up. A job that declares an expected wall gets a per-job budget — a generous
// multiple of that estimate, floored, and capped by the MaxJobDuration backstop; a job
// with no estimate falls back to the flat backstop. This is a backstop against a hung
// compute, never the normal completion path (which is the compute returning, or an
// out-of-band abandon directive).
func (r *Runner) jobBudget(g *wire.Grant) time.Duration {
	backstop := time.Duration(r.cfg.MaxJobDurationS) * time.Second
	if g.Job.ExpectedWallS <= 0 {
		return backstop
	}
	budget := time.Duration(g.Job.ExpectedWallS*jobBudgetMultiple) * time.Second
	if budget < jobBudgetFloor {
		budget = jobBudgetFloor
	}
	if budget > backstop {
		budget = backstop
	}
	return budget
}

// processJob executes one granted job through its full lifecycle and reports the
// appropriate terminal verb. It never returns an error; failures are reported to
// the dispatcher.
func (r *Runner) processJob(ctx context.Context, dc *dispatcherConn, g *wire.Grant) {
	// The job's execution budget is per-job (jobBudget) — NOT the lease deadline. The
	// lease TTL (g.Lease.DeadlineTS) is a crash-detection timer the heartbeat renews
	// every interval; using it as the job deadline would cancel any op longer than one
	// lease TTL (a long transcription) mid-run, failing it and leaving the compute
	// running an orphan. Cancellation for real arrives out of band via the heartbeat's
	// abandon directive (markAbandoned); this deadline is only a backstop against a
	// wedged compute.
	deadline := time.Time{}
	jobCtx, cancel := context.WithCancel(ctx)
	if !r.cfg.NoDeadline {
		cancel()
		deadline = time.Now().Add(r.jobBudget(g))
		jobCtx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()
	r.setCurrent(&liveJob{leaseID: g.Lease.LeaseID, jobID: g.Job.JobID, cancel: cancel})
	defer r.clearCurrent()

	workdir := filepath.Join(r.cfg.WorkRoot, g.Job.JobID)
	_ = os.RemoveAll(workdir)
	if err := os.MkdirAll(filepath.Join(workdir, "outputs"), 0o755); err != nil {
		r.release(dc, g, wire.ReleaseShipping, "mkdir workdir: "+err.Error())
		return
	}
	defer os.RemoveAll(workdir)

	// 1. Fetch + verify the invocation (its address is the computation identity).
	invBytes, err := r.cas.GetBytes(jobCtx, g.Job.InvocationAddress)
	if err != nil {
		r.releaseForCAS(dc, g, err)
		return
	}
	var inv artifact.Invocation
	if err := json.Unmarshal(invBytes, &inv); err != nil {
		r.release(dc, g, wire.ReleaseIntegrity, "invocation parse: "+err.Error())
		return
	}
	if err := inv.Validate(); err != nil {
		r.release(dc, g, wire.ReleaseIntegrity, "invocation invalid: "+err.Error())
		return
	}

	// 2. Lay out inputs (verified, traversal-guarded).
	if err := r.cas.LayoutInputs(jobCtx, workdir, &inv); err != nil {
		r.releaseForCAS(dc, g, err)
		return
	}

	// 3. Invoke the compute container. The compute is single-flight; if it is busy
	// with another invoke (typically an abandoned run still finishing server-side),
	// hold this lease and wait rather than failing — see invokeWaitingForFreeCompute.
	inputs := map[string]string{}
	for name := range inv.Inputs {
		inputs[name] = filepath.ToSlash(filepath.Join("inputs", name))
	}
	deadlineTS := int64(0)
	if !deadline.IsZero() {
		deadlineTS = deadline.UnixMilli()
	}
	res, failure, ierr := r.invokeWaitingForFreeCompute(jobCtx, g, InvokeRequest{
		JobID:      g.Job.JobID,
		Invocation: invBytes,
		Workdir:    workdir,
		Inputs:     inputs,
		OutputsDir: "outputs",
		DeadlineTS: deadlineTS, // zero explicitly means no execution deadline
	})
	if ierr != nil {
		// Transport/protocol fault. If we were told to abandon (ctx cancelled),
		// stay silent — the job was cancelled server-side.
		if jobCtx.Err() != nil && ctx.Err() == nil && r.wasAbandoned(g.Job.JobID) {
			return
		}
		if errors.Is(ierr, context.DeadlineExceeded) {
			r.fail(dc, g, wire.ClassTimeout, "invoke deadline exceeded")
			return
		}
		r.fail(dc, g, wire.ClassFatal, "invoke transport: "+ierr.Error())
		return
	}
	if failure != nil {
		class := mapErrorClass(failure.ErrClass)
		r.fail(dc, g, class, failure.Message)
		return
	}

	// 4. Upload outputs and report completion.
	// A command returns its final result after stopping its children. Shipping
	// that result uses the runner's live context after a cancellation request.
	if len(r.cfg.Command) != 0 {
		jobCtx = ctx
	}
	if err := r.flushLog(jobCtx, dc); err != nil {
		r.release(dc, g, wire.ReleaseShipping, "command log: "+err.Error())
		return
	}
	outputs := map[string]artifact.Output{}
	for name, rel := range res.Outputs {
		full := filepath.Join(workdir, filepath.FromSlash(rel))
		addr, size, err := r.cas.PutFile(jobCtx, full)
		if err != nil {
			r.release(dc, g, wire.ReleaseShipping, fmt.Sprintf("upload %s: %v", name, err))
			return
		}
		outputs[name] = artifact.Output{Address: addr, Size: size}
	}
	ar := artifact.ActionResult{
		Kind:              artifact.ActionResultKind,
		InvocationAddress: g.Job.InvocationAddress,
		Outputs:           outputs,
		Metrics:           res.Metrics,
		Runner:            artifact.RunnerInfo{Node: r.cfg.Node, Version: r.cfg.Version},
	}
	if ar.Metrics == nil {
		ar.Metrics = map[string]int64{}
	}
	r.complete(dc, g, ar)
}

// ComputeBusyRetryInterval is how long the runner waits before retrying an invoke
// that a single-flight compute rejected as busy (409). Exported so tests can shorten it.
var ComputeBusyRetryInterval = 5 * time.Second

// invokeWaitingForFreeCompute invokes the compute, holding the lease and waiting
// through a 409 (compute busy) instead of failing the job. The compute serves one
// invoke at a time; a busy response means another invoke — typically an abandoned
// run still finishing server-side — holds the slot. Failing here would burn the
// entire queue into instant 409s while one run drains (the observed drain-collapse
// tail after the keep-alive fix). Instead we keep this job leased (the heartbeat
// renews it) and retry until the compute frees or the deadline/abandon fires; a
// cancelled ctx returns its error, handled as abandon/timeout by the caller.
func (r *Runner) invokeWaitingForFreeCompute(
	ctx context.Context, g *wire.Grant, req InvokeRequest,
) (*InvokeResult, *InvokeFailure, error) {
	loggedBusy := false
	for {
		res, failure, ierr := r.invoke.Invoke(ctx, req)
		if _, busy := ierr.(ErrBusy); !busy {
			return res, failure, ierr
		}
		if !loggedBusy {
			r.log.Info("compute busy; holding job, waiting for the compute to free", "job", g.Job.JobID)
			loggedBusy = true
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(ComputeBusyRetryInterval):
		}
	}
}

// --- terminal verb senders ---

func (r *Runner) complete(dc *dispatcherConn, g *wire.Grant, ar artifact.ActionResult) {
	env, err := dc.call(wire.TypeComplete, wire.Complete{
		LeaseID: g.Lease.LeaseID, JobID: g.Job.JobID, Attempt: g.Job.Attempt, ActionResult: ar,
	})
	if err != nil {
		r.log.Warn("complete send failed", "job", g.Job.JobID, "err", err)
		return
	}
	if e := asError(env); e != nil {
		// not_leaseholder means the lease expired and the job was re-queued or
		// taken; the result is discarded. Nothing to do.
		r.log.Info("complete rejected", "job", g.Job.JobID, "code", e.Code, "msg", e.Message)
	}
}

func (r *Runner) fail(dc *dispatcherConn, g *wire.Grant, class wire.ErrorClass, msg string) {
	env, err := dc.call(wire.TypeFail, wire.Fail{
		LeaseID: g.Lease.LeaseID, JobID: g.Job.JobID, Attempt: g.Job.Attempt, ErrorClass: class, Message: truncate(msg, 4096),
	})
	if err != nil {
		r.log.Warn("fail send failed", "job", g.Job.JobID, "err", err)
		return
	}
	if e := asError(env); e != nil {
		r.log.Info("fail rejected", "job", g.Job.JobID, "code", e.Code)
	}
}

func (r *Runner) release(dc *dispatcherConn, g *wire.Grant, reason wire.ReleaseReason, msg string) {
	r.log.Info("release", "job", g.Job.JobID, "reason", reason, "detail", msg)
	env, err := dc.call(wire.TypeRelease, wire.Release{LeaseID: g.Lease.LeaseID, JobID: g.Job.JobID, Reason: reason})
	if err != nil {
		r.log.Warn("release send failed", "job", g.Job.JobID, "err", err)
		return
	}
	if e := asError(env); e != nil {
		r.log.Info("release rejected", "job", g.Job.JobID, "code", e.Code)
	}
}

func (r *Runner) releaseForCAS(dc *dispatcherConn, g *wire.Grant, err error) {
	var ce *casError
	reason := wire.ReleaseCASUnreachable
	if errors.As(err, &ce) {
		switch ce.kind {
		case casMiss:
			reason = wire.ReleaseCASMiss
		case casIntegrity:
			reason = wire.ReleaseIntegrity
		case casUnreachable:
			reason = wire.ReleaseCASUnreachable
		default:
			reason = wire.ReleaseCASUnreachable
		}
	}
	r.release(dc, g, reason, err.Error())
}

// mapErrorClass maps a compute-reported error_class string onto the wire enum,
// defaulting unrecognized values to unknown.
func mapErrorClass(s string) wire.ErrorClass {
	c := wire.ErrorClass(s)
	if wire.ValidErrorClasses[c] {
		return c
	}
	return wire.ClassUnknown
}

func (r *Runner) wasAbandoned(jobID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current != nil && r.current.jobID == jobID && r.current.abandoned
}

func (r *Runner) throttleWait() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.leaseAfter == 0 {
		return 0
	}
	now := time.Now().UnixMilli()
	if r.leaseAfter <= now {
		return 0
	}
	return time.Duration(r.leaseAfter-now) * time.Millisecond
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
