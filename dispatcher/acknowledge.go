package dispatcher

import (
	"context"

	"github.com/falahat/dispatch-service/internal/wire"
)

// AcknowledgeLocal drains results already persisted by an owner-controlled local
// command. Network applications keep their existing explicit domain-persistence ack.
func (d *Dispatcher) AcknowledgeLocal(ctx context.Context) error {
	for {
		wake := d.leaseWake.wait()
		batch, err := d.persistingBatch(nil)
		if err != nil {
			return err
		}
		for _, result := range batch {
			if err := d.Ack(wire.Ack{JobID: result.JobID, Disposition: wire.DispositionPersisted}); err != nil {
				return err
			}
		}
		if len(batch) != 0 {
			continue
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return nil
		}
	}
}
