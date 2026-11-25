package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

// Run drives the runner: boot readiness gate, then, while the compute stays ready,
// lease -> fetch -> invoke -> put -> complete, with a concurrent heartbeat/directive
// channel. It returns on drain, and nil once ctx is cancelled wherever it waits: a
// runner stopped at its boot gate or while dialing was stopped, not failed, so its
// unit must not read failed.
func (r *Runner) Run(ctx context.Context) error {
	err := r.run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (r *Runner) run(ctx context.Context) error {
	// Boot gate: the compute must be ready and serving the expected op before
	// this runner joins the fleet (INVOKE.md).
	if _, err := r.invoke.WaitReady(ctx); err != nil {
		return fmt.Errorf("runner: compute not ready: %w", err)
	}

	work, workOK, err := dialDispatcher(ctx, r.cfg.DispatcherAddr, r.ident(), r.wrapper)
	if err != nil {
		return err
	}
	defer func() {
		if work != nil {
			work.close()
		}
	}()

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
	computeDown := false
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
		// A compute that is down or still warming up takes no job: one leased now would
		// only fail. Ask again each second, hearing drain and shutdown in between.
		if !r.computeReady(ctx) {
			if !computeDown {
				r.log.Warn("compute not ready; taking no work until it is")
			}
			computeDown = true
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		if computeDown {
			r.log.Info("compute ready; taking work again")
			computeDown = false
		}

		grant, err := r.lease(ctx, work)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.log.Warn("lease error; reconnecting", "err", err)
			work.close()
			for {
				work, err = r.redial(ctx)
				if err == nil {
					break
				}
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

// stopReportTimeout bounds how long a stopping runner waits for the dispatcher to
// take a report: the container runtime kills it 10 s after asking it to stop.
const stopReportTimeout = 5 * time.Second

// send sends a job's result, failure or release, and sends it again over a new
// connection if the work connection died while the job ran or the reply did not come
// within replyTimeout. A PEP or dispatcher restart drops every runner connection, but
// the lease lives on in the dispatcher under this runner's identity. Lost with the old
// connection, the report left the job to wait out its lease and run again on a new
// attempt. A report the dispatcher already took, its reply lost, is an exact replay it
// answers as before, so sending one twice is safe. A stopping runner tries once, for at
// most stopReportTimeout; a report that does not arrive leaves the job to its lease.
func (r *Runner) send(ctx context.Context, dc *dispatcherConn, typ string, body any) (wire.Envelope, error) {
	if ctx.Err() != nil {
		return dc.call(typ, body, stopReportTimeout)
	}
	env, err := dc.call(typ, body, replyTimeout)
	if err == nil {
		return env, nil
	}
	if r.reconnect(ctx, dc) != nil {
		return env, err
	}
	r.log.Warn("work connection lost; reporting over a new one", "frame", typ, "err", err)
	return dc.call(typ, body, replyTimeout)
}

// reconnect gives dc a new connection in place of its dead one.
func (r *Runner) reconnect(ctx context.Context, dc *dispatcherConn) error {
	fresh, err := r.redial(ctx)
	if err != nil {
		return err
	}
	dc.renew(fresh)
	return nil
}

// lease long-polls for a job. A nil grant with nil error means "no work".
func (r *Runner) lease(ctx context.Context, dc *dispatcherConn) (*wire.Grant, error) {
	gpus := r.offerGPUs(ctx) // before the wait starts: a slow reading must not use up the long-poll's time
	wait := time.Duration(r.cfg.LeaseWaitS+15) * time.Second
	env, err := dc.call(wire.TypeLease, wire.Lease{Lanes: r.cfg.Lanes, WaitS: r.cfg.LeaseWaitS, GPUs: gpus}, wait)
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
		empty, err := wire.DecodeBody[wire.Empty](env)
		if err != nil {
			return nil, err
		}
		if empty.Reason == "drained" {
			r.setDraining()
		}
		waitToLeaseAgain(ctx, empty)
		return nil, nil
	default:
		return nil, fmt.Errorf("lease: unexpected reply %s", env.Type)
	}
}

// maxRetryAfter bounds how long an empty lease's retry_after_s keeps the runner from
// asking again.
const maxRetryAfter = time.Minute

// waitToLeaseAgain waits as long as an empty lease asks before the next lease. The
// dispatcher answers at once, without waiting for work, while the runner's lanes are in
// backpressure or it is over its rate cap, so asking again at once would spin: every ask
// is a frame through the PEP, which verifies it and stores its nonce.
func waitToLeaseAgain(ctx context.Context, empty wire.Empty) {
	if empty.RetryAfterS == nil || *empty.RetryAfterS <= 0 {
		return
	}
	wait := time.Duration(min(*empty.RetryAfterS, int(maxRetryAfter/time.Second))) * time.Second
	select {
	case <-ctx.Done():
	case <-time.After(wait):
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
	// A workdir left by a crash goes before the job is current, so a heartbeat never
	// ships an earlier attempt's invoke.log as this one's.
	workdir := filepath.Join(r.cfg.WorkRoot, g.Job.JobID)
	_ = os.RemoveAll(workdir)
	r.setCurrent(&liveJob{leaseID: g.Lease.LeaseID, jobID: g.Job.JobID, cancel: cancel,
		logBase: g.Job.LogOffset, logOffset: g.Job.LogOffset})
	defer r.clearCurrent()

	outputsPath := filepath.Join(workdir, outputsDir)
	if err := os.MkdirAll(outputsPath, 0o755); err != nil {
		r.release(ctx, dc, g, wire.ReleaseShipping, "mkdir workdir: "+err.Error())
		return
	}
	defer os.RemoveAll(workdir)
	madeOutputs, err := os.Lstat(outputsPath)
	if err != nil {
		r.release(ctx, dc, g, wire.ReleaseShipping, "stat outputs: "+err.Error())
		return
	}

	// 1. Fetch + verify the invocation (its address is the computation identity).
	invBytes, err := r.cas.GetBytes(jobCtx, g.Job.InvocationAddress)
	if err != nil {
		r.releaseForCAS(ctx, dc, g, err)
		return
	}
	var inv artifact.Invocation
	if err := json.Unmarshal(invBytes, &inv); err != nil {
		r.release(ctx, dc, g, wire.ReleaseIntegrity, "invocation parse: "+err.Error())
		return
	}
	if err := inv.Validate(); err != nil {
		r.release(ctx, dc, g, wire.ReleaseIntegrity, "invocation invalid: "+err.Error())
		return
	}

	// 2. Find local inputs where they lie, then fetch the rest (verified,
	// traversal-guarded). A local input on another node means the job was placed
	// on the wrong machine; one this node lacks is the job's fault.
	local, err := r.localInputs(&inv)
	var elsewhere *wrongNode
	if errors.As(err, &elsewhere) {
		r.release(ctx, dc, g, wire.ReleaseWrongHardware, err.Error())
		return
	}
	if err != nil {
		r.fail(ctx, dc, g, wire.ClassBadInput, err.Error())
		return
	}
	if err := r.cas.LayoutInputs(jobCtx, workdir, &inv); err != nil {
		r.releaseForCAS(ctx, dc, g, err)
		return
	}

	// 3. Invoke the compute container. The compute is single-flight; if it is busy
	// with another invoke (typically an abandoned run still finishing server-side),
	// hold this lease and wait rather than failing — see invokeWaitingForFreeCompute.
	// A GPU job first takes the machine's GPU lock, when one is configured.
	if g.Job.GPU != nil && !r.wasOffered(g.Job.GPU) {
		r.release(ctx, dc, g, wire.ReleaseWrongHardware, "granted a GPU this runner did not offer")
		return
	}
	if g.Job.GPU != nil && r.cfg.GPULock != "" {
		unlock, err := takeGPULock(jobCtx, r.cfg.GPULock)
		if err != nil {
			if r.cutShort(ctx, jobCtx, dc, g) {
				return
			}
			r.release(ctx, dc, g, wire.ReleaseWrongHardware, "gpu lock: "+err.Error())
			return
		}
		defer unlock()
	}
	inputs := map[string]string{}
	for name := range inv.Inputs {
		inputs[name] = filepath.ToSlash(filepath.Join("inputs", name))
	}
	for name, path := range local {
		inputs[name] = path
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
		OutputsDir: outputsDir,
		DeadlineTS: deadlineTS, // zero explicitly means no execution deadline
		Roots:      r.cfg.Roots,
		GPU:        g.Job.GPU,
	})
	if ierr != nil {
		if r.cutShort(ctx, jobCtx, dc, g) {
			return
		}
		if errors.Is(ierr, context.DeadlineExceeded) {
			r.fail(ctx, dc, g, wire.ClassTimeout, "invoke deadline exceeded")
			return
		}
		if unreachedCompute(ierr) {
			// The compute went down after this job was leased, before the invoke reached
			// it. That says nothing about the job, so it goes straight back to the queue,
			// and the loop takes no new job until the compute answers ready.
			r.release(ctx, dc, g, wire.ReleaseInterrupted, "compute unreachable: "+ierr.Error())
			return
		}
		if droppedByCompute(ierr) {
			// The compute took the invoke and dropped it before answering in full: it
			// died or was restarted mid-job, perhaps by this job, so the job runs again
			// within its max_attempts.
			r.fail(ctx, dc, g, wire.ClassUnknown, "compute dropped the invoke: "+ierr.Error())
			return
		}
		r.fail(ctx, dc, g, wire.ClassFatal, ierr.Error()) // the compute broke the protocol
		return
	}
	if failure != nil {
		if ctx.Err() != nil {
			// A command stopped with the runner says nothing about its job.
			r.release(ctx, dc, g, wire.ReleaseInterrupted, "the runner is stopping")
			return
		}
		// A command's log tail is usually why it failed: ship it before the failure,
		// on the runner's live context, as a result's log is shipped before it.
		if err := r.flushLog(ctx, dc); err != nil {
			r.log.Warn("command log before its failure", "job", g.Job.JobID, "err", err)
		}
		r.fail(ctx, dc, g, mapErrorClass(failure.ErrClass), failure.Message)
		return
	}

	// 4. Upload outputs and report completion.
	// A command returns its final result after stopping its children. Shipping
	// that result uses the runner's live context after a cancellation request.
	if len(r.cfg.Command) != 0 {
		jobCtx = ctx
	}
	// The log goes ahead of the result, but a log that cannot be shipped does not cost
	// the job its result: released, the finished job would run again.
	if err := r.flushLog(jobCtx, dc); err != nil {
		r.log.Warn("command log before its result", "job", g.Job.JobID, "err", err)
	}
	outputs, err := r.publishOutputs(jobCtx, outputsPath, madeOutputs, res.Outputs)
	var broken *outputViolation
	if errors.As(err, &broken) {
		r.fail(ctx, dc, g, wire.ClassFatal, broken.Error())
		return
	}
	if err != nil {
		r.release(ctx, dc, g, wire.ReleaseShipping, "upload outputs: "+err.Error())
		return
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
	// A result the dispatcher would refuse (bad names, too many outputs) is the
	// compute's fault; failing it now beats leaving the lease to expire.
	if err := ar.Validate(); err != nil {
		r.fail(ctx, dc, g, wire.ClassFatal, "action result: "+err.Error())
		return
	}
	r.complete(ctx, dc, g, ar)
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

func (r *Runner) complete(ctx context.Context, dc *dispatcherConn, g *wire.Grant, ar artifact.ActionResult) {
	env, err := r.send(ctx, dc, wire.TypeComplete, wire.Complete{
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

func (r *Runner) fail(ctx context.Context, dc *dispatcherConn, g *wire.Grant, class wire.ErrorClass, msg string) {
	env, err := r.send(ctx, dc, wire.TypeFail, wire.Fail{
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

func (r *Runner) release(ctx context.Context, dc *dispatcherConn, g *wire.Grant, reason wire.ReleaseReason, msg string) {
	r.log.Info("release", "job", g.Job.JobID, "reason", reason, "detail", msg)
	env, err := r.send(ctx, dc, wire.TypeRelease, wire.Release{LeaseID: g.Lease.LeaseID, JobID: g.Job.JobID, Reason: reason})
	if err != nil {
		r.log.Warn("release send failed", "job", g.Job.JobID, "err", err)
		return
	}
	if e := asError(env); e != nil {
		r.log.Info("release rejected", "job", g.Job.JobID, "code", e.Code)
	}
}

func (r *Runner) releaseForCAS(ctx context.Context, dc *dispatcherConn, g *wire.Grant, err error) {
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
	r.release(ctx, dc, g, reason, err.Error())
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

// cutShort settles a job whose wait or invoke ended because the job was abandoned
// or the runner is stopping, and reports whether it did. Neither is the job
// failing. An abandoned job was settled by the dispatcher, so nothing is sent. A
// stopping runner releases its job as interrupted, so the job runs again at once
// on the same attempt; left to its lease, it waited out the TTL and used up an
// attempt, and on its last one failed as lease_expired.
func (r *Runner) cutShort(ctx, jobCtx context.Context, dc *dispatcherConn, g *wire.Grant) bool {
	if jobCtx.Err() == nil {
		return false
	}
	if ctx.Err() != nil {
		r.release(ctx, dc, g, wire.ReleaseInterrupted, "the runner is stopping")
		return true
	}
	return r.wasAbandoned(g.Job.JobID)
}

// computeReady probes the compute once, briefly: one that does not answer in time
// reads as not ready rather than stalling the loop.
func (r *Runner) computeReady(ctx context.Context) bool {
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	health, err := r.invoke.Healthz(probe)
	return err == nil && health.Ready
}

// unreachedCompute reports whether an invoke failed to connect to the compute at
// all, so the request never reached it. A connection the compute dropped mid-invoke
// is not this: that stays fatal (INVOKE.md).
func unreachedCompute(err error) bool {
	var dial *net.OpError
	return errors.As(err, &dial) && dial.Op == "dial"
}

// droppedByCompute reports whether the connection broke before the compute's whole
// answer arrived (Invoke's *url.Error); a compute that answers in full but breaks
// the protocol did not drop the invoke.
func droppedByCompute(err error) bool {
	var transport *url.Error
	return errors.As(err, &transport)
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
