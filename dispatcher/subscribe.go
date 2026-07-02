package dispatcher

import "github.com/falahat/dispatch-service/internal/wire"

// persistingBatch returns the current PERSISTING inbox as completions,
// oldest-first, excluding job_ids already delivered in this subscription
// session. Correctness lives here (the durable inbox), not in any channel: a
// reconnect re-reads the inbox and redelivers exactly the un-acked set, because
// ack is what removes a job from PERSISTING.
func (d *Dispatcher) persistingBatch(exclude map[string]bool) ([]wire.Completion, error) {
	rows, err := d.store.db.Query(
		`SELECT ` + jobColumns + ` FROM jobs WHERE state='PERSISTING' ORDER BY completed_ts ASC, job_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wire.Completion
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		if exclude[j.JobID] {
			continue
		}
		c, err := buildCompletion(j)
		if err != nil {
			// A corrupt inbox row is skipped, not fatal to the whole stream.
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// subWait returns the channels a subscription streamer selects on: a wake
// (a completion may be available) and a takeover (superseded by a newer sub).
func (s *subscription) waitChans() (<-chan struct{}, <-chan struct{}) {
	return s.wake, s.takeover
}
