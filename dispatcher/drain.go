package dispatcher

import (
	"context"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Drain closes admission before waiting. Existing work keeps its lease and finishes.
func (d *Dispatcher) drain(ctx context.Context, id string, draining bool) *wire.Error {
	if len(id) == 0 || len(id) > 128 {
		return &wire.Error{Code: wire.CodeInvalid, Message: "invalid runner_id"}
	}
	result, err := d.store.db.Exec(`UPDATE runners SET draining=? WHERE runner_id=?`, draining, id)
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
	}
	count, err := result.RowsAffected()
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
	}
	if count == 0 {
		return &wire.Error{Code: wire.CodeGone, Message: "unknown runner"}
	}
	d.wakeLeases()
	for draining {
		wake := d.leaseWake.wait()
		var running int
		if err := d.store.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE state='RUNNING' AND lease_runner_id=?`, id).Scan(&running); err != nil {
			return &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
		}
		if running == 0 {
			return nil
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return &wire.Error{Code: wire.CodeGone, Message: "dispatcher shutting down; runner remains draining"}
		}
	}
	return nil
}
