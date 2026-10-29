package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// heartbeatLoop renews the current lease and applies steering directives. It
// runs on a dedicated connection so it never contends with the work loop, and
// keeps the fleet row fresh even while idle.
//
// It OWNS its connection's lifecycle and reconnects on failure: a dead heartbeat
// connection is not benign — it stops the dispatcher-side lease renewal, so the
// in-flight job hits the lease TTL, gets reclaimed + requeued mid-run, and the
// re-lease invokes a compute that is still busy with the orphaned run. That is
// exactly the failure mode that silently collapses a drain, so the heartbeat must
// heal its connection the same way the work loop already does.
func (r *Runner) heartbeatLoop(ctx context.Context, dc *dispatcherConn, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	defer func() { dc.close() }() // close whichever connection we currently hold
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.beat(ctx, dc); err != nil {
				r.log.Warn("heartbeat send failed; reconnecting", "err", err)
				dc.close()
				nd, derr := r.redial(ctx)
				if derr != nil {
					if ctx.Err() != nil {
						return
					}
					r.log.Warn("heartbeat reconnect failed; retrying next tick", "err", derr)
					continue
				}
				dc = nd
			}
		}
	}
}

// beat sends one heartbeat and applies the returned directives. A non-nil error
// means the connection is dead (the caller reconnects); a protocol-level
// rejection or decode error is logged but is not a dead connection.
func (r *Runner) beat(ctx context.Context, dc *dispatcherConn) error {
	r.progressMu.Lock()
	defer r.progressMu.Unlock()
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	r.refreshGPU(probe) // fold in the compute's live GPU/VRAM before we send
	cancel()
	status, lease := r.currentStatus()
	chunk, logErr := r.logChunk(ctx)
	env, err := dc.call(wire.TypeHeartbeat, wire.Heartbeat{Status: status, LeaseID: lease, Log: chunk})
	if err != nil {
		return err // dead connection -> caller reconnects so lease renewal resumes
	}
	if e := asError(env); e != nil {
		r.log.Warn("heartbeat rejected", "code", e.Code, "msg", e.Message)
		return nil
	}
	beat, err := wire.DecodeBody[wire.BeatOK](env)
	if err != nil {
		r.log.Warn("heartbeat decode", "err", err)
		return nil
	}
	for _, dir := range beat.Directives {
		switch dir.Kind {
		case wire.DirectiveAbandon:
			r.log.Info("directive: abandon", "job", dir.JobID)
			r.markAbandoned(dir.JobID)
		case wire.DirectiveDrain:
			r.log.Info("directive: drain")
			r.setDraining()
		case wire.DirectiveThrottle:
			if dir.LeaseAfterTS != nil {
				r.setLeaseAfter(*dir.LeaseAfterTS)
			}
		}
	}
	if logErr != nil {
		return logErr
	}
	if chunk != nil {
		if beat.LogOffset == nil || *beat.LogOffset != chunk.Offset+chunk.Size {
			return fmt.Errorf("dispatcher did not acknowledge the command log chunk")
		}
		r.mu.Lock()
		if r.current != nil && r.current.jobID == status.CurrentJobID {
			r.current.logOffset = *beat.LogOffset
		}
		r.mu.Unlock()
	}
	return nil
}
