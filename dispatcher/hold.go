package dispatcher

import (
	"context"
	"database/sql"

	"github.com/falahat/dispatch-service/internal/wire"
)

// hold stops every runner of a node, connected now or later, from taking new work; they
// stay connected and wait in the long-poll. Holding then waits, like drain, for the work
// the node is running to settle, without cancelling it. Unhold lets the node take work at
// once. A node is the name runners give at hello, so a node never seen can be held.
func (d *Dispatcher) hold(ctx context.Context, node, reason string, held bool) *wire.Error {
	if len(node) == 0 || len(node) > 128 || len(reason) > 1024 {
		return &wire.Error{Code: wire.CodeInvalid, Message: "hold: node of 1..128 bytes and reason of at most 1024 required"}
	}
	var err error
	if held {
		_, err = d.store.db.Exec(`INSERT INTO node_holds(node, reason, since_ts) VALUES(?,?,?)
			ON CONFLICT(node) DO UPDATE SET reason=excluded.reason`, node, reason, d.now())
	} else {
		_, err = d.store.db.Exec(`DELETE FROM node_holds WHERE node=?`, node)
	}
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
	}
	d.wakeLeases()
	for held {
		wake := d.leaseWake.wait()
		var running int
		if err := d.store.db.QueryRow(`SELECT COUNT(*) FROM jobs j JOIN runners r ON r.runner_id=j.lease_runner_id
			WHERE j.state='RUNNING' AND r.node=?`, node).Scan(&running); err != nil {
			return &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
		}
		if running == 0 {
			return nil
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return &wire.Error{Code: wire.CodeGone, Message: "dispatcher shutting down; node remains held"}
		}
	}
	return nil
}

// runnerHeld reports whether the runner's node is held.
func runnerHeld(tx *sql.Tx, runnerID string) (bool, error) {
	var held bool
	err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM node_holds h JOIN runners r ON r.node=h.node
		WHERE r.runner_id=?)`, runnerID).Scan(&held)
	return held, err
}
