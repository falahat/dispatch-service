package runner

import (
	"context"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// heartbeatLoop renews the current lease and applies steering directives. It
// runs on a dedicated connection so it never contends with the work loop, and
// keeps the fleet row fresh even while idle.
func (r *Runner) heartbeatLoop(ctx context.Context, dc *dispatcherConn, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.beat(dc)
		}
	}
}

func (r *Runner) beat(dc *dispatcherConn) {
	status, lease := r.currentStatus()
	env, err := dc.call(wire.TypeHeartbeat, wire.Heartbeat{Status: status, LeaseID: lease})
	if err != nil {
		r.log.Warn("heartbeat send failed", "err", err)
		return
	}
	if e := asError(env); e != nil {
		r.log.Warn("heartbeat rejected", "code", e.Code, "msg", e.Message)
		return
	}
	beat, err := wire.DecodeBody[wire.BeatOK](env)
	if err != nil {
		r.log.Warn("heartbeat decode", "err", err)
		return
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
}
