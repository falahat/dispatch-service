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

// processJob executes one granted job through its full lifecycle and reports the
// appropriate terminal verb. It never returns an error; failures are reported to
// the dispatcher.
func (r *Runner) processJob(ctx context.Context, dc *dispatcherConn, g *wire.Grant) {
	deadline := time.UnixMilli(g.Lease.DeadlineTS)
	jobCtx, cancel := context.WithDeadline(ctx, deadline)
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

	// 3. Invoke the compute container.
	inputs := map[string]string{}
	for name := range inv.Inputs {
		inputs[name] = filepath.ToSlash(filepath.Join("inputs", name))
	}
	res, failure, ierr := r.invoke.Invoke(jobCtx, InvokeRequest{
		JobID:      g.Job.JobID,
		Invocation: invBytes,
		Workdir:    workdir,
		Inputs:     inputs,
		OutputsDir: "outputs",
		DeadlineTS: g.Lease.DeadlineTS,
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
		if _, busy := ierr.(ErrBusy); busy {
			r.fail(dc, g, wire.ClassUnknown, "compute busy (unexpected concurrent invoke)")
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
