package dispatcher

import "database/sql"

// silentAfterBeats is how many heartbeat intervals a runner may go unheard (no hello, no
// heartbeat) before it is granted nothing: it may have gone without a close. Its
// connections can outlive it, since a relay in front of the PEP (Tailscale Serve) holds
// them open and answers TCP keepalive for it, so the heartbeat, sent on its own
// connection even while idle, is the dispatcher's one sign that it is still there (D20).
const silentAfterBeats = 2

// heardSince is how recently a runner must have been heard at now to be granted work. The
// fleet view counts the same runners online, so a runner granted nothing shows why.
func (d *Dispatcher) heardSince(now int64) int64 {
	return now - int64(silentAfterBeats*d.cfg.HeartbeatIntervalS)*1000
}

// heard reports whether a runner last heard at lastSeen may be granted work at now. A
// silent runner's waiting lease asks again every pollInterval, so only the first refusal
// of each silent spell is logged, and the end of the spell once the runner is heard.
func (d *Dispatcher) heard(runnerID string, lastSeen, now int64) bool {
	heard := lastSeen >= d.heardSince(now)
	d.silentMu.Lock()
	defer d.silentMu.Unlock()
	switch {
	case !heard && !d.silent[runnerID]:
		d.silent[runnerID] = true
		d.log.Warn("runner silent; granting it nothing until it is heard again (D20)",
			"runner", runnerID, "last_seen_ts", lastSeen)
	case heard && d.silent[runnerID]:
		delete(d.silent, runnerID)
		d.log.Info("runner heard again after a silent spell", "runner", runnerID)
	}
	return heard
}

// runnerLastSeen returns when the runner was last heard from, or 0 for a runner with no
// fleet row: it has never said hello.
func runnerLastSeen(tx *sql.Tx, runnerID string) (int64, error) {
	var lastSeen sql.NullInt64
	err := tx.QueryRow(`SELECT last_seen_ts FROM runners WHERE runner_id=?`, runnerID).Scan(&lastSeen)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return lastSeen.Int64, err
}
