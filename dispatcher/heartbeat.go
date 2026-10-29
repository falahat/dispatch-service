package dispatcher

import (
	"database/sql"
	"encoding/json"
	"math"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Hello upserts the fleet row for a runner and returns the server parameters.
// runner.id is the runner's public-key fingerprint; in production the PEP has
// already verified it matches the authenticated key, so the dispatcher trusts it.
func (d *Dispatcher) Hello(req wire.Hello) (wire.HelloOK, *wire.Error) {
	if req.Contract != wire.ContractVersion {
		return wire.HelloOK{}, &wire.Error{Code: wire.CodeVersionMismatch, Message: "hello: contract " + req.Contract}
	}
	if req.Runner.ID == "" || len(req.Runner.Lanes) == 0 {
		return wire.HelloOK{}, &wire.Error{Code: wire.CodeInvalid, Message: "hello: runner id + lanes required"}
	}
	now := d.now()
	err := d.store.writeTx(func(tx *sql.Tx) error {
		return upsertRunner(tx, req.Runner.ID, wire.HeartbeatStatus{
			Node: req.Runner.Node, Lanes: req.Runner.Lanes, Capacity: req.Runner.Capacity,
		}, req.Runner.Version, now)
	})
	if err != nil {
		return wire.HelloOK{}, &wire.Error{Code: wire.CodeInternal, Message: "hello: " + err.Error()}
	}
	return wire.HelloOK{
		ServerTS:           now,
		HeartbeatIntervalS: d.cfg.HeartbeatIntervalS,
		MinWaitS:           d.cfg.MinWaitS,
		MaxWaitS:           d.cfg.MaxWaitS,
	}, nil
}

// Heartbeat renews the named lease and returns steering directives — the only
// channel by which the dispatcher tells a runner to abandon, drain, or throttle.
func (d *Dispatcher) Heartbeat(runnerID string, req wire.Heartbeat) (wire.BeatOK, *wire.Error) {
	out := wire.BeatOK{Directives: []wire.Directive{}}
	if req.Log != nil && (req.LeaseID == "" || req.Log.Offset < 0 || req.Log.Size < 1 || req.Log.Size > 1<<20 || req.Log.Offset > math.MaxInt64-req.Log.Size || req.Log.Address.Validate() != nil) {
		return out, &wire.Error{Code: wire.CodeInvalid, Message: "invalid log chunk"}
	}
	err := d.store.writeTx(func(tx *sql.Tx) error {
		now := d.now()
		if err := upsertRunner(tx, runnerID, req.Status, "", now); err != nil {
			return err
		}
		q, err := runnerQuarantined(tx, runnerID)
		if err != nil {
			return err
		}
		draining, err := runnerDraining(tx, runnerID)
		if err != nil {
			return err
		}
		if draining {
			out.Directives = append(out.Directives, wire.Directive{Kind: wire.DirectiveDrain})
		}

		if req.LeaseID != "" {
			jobID, err := jobIDForLease(tx, req.LeaseID)
			if err != nil {
				return err
			}
			var live Job
			found := false
			if jobID != "" {
				live, err = getJobTx(tx, jobID)
				if err != nil && err != sql.ErrNoRows {
					return err
				}
				found = err == nil
			}
			if found && live.State == "RUNNING" && live.LeaseID == req.LeaseID && live.LeaseRunnerID == runnerID {
				if q || live.CancelRequested {
					out.Directives = append(out.Directives, wire.Directive{Kind: wire.DirectiveAbandon, JobID: jobID})
				}
				if !q && (!live.CancelRequested || d.cfg.WaitForExecutor) {
					// Renew the lease (fenced: only the live holder gets here).
					deadline := now + int64(d.cfg.LeaseTTLS)*1000
					if _, err := tx.Exec(
						`UPDATE jobs SET lease_deadline_ts=?, updated_ts=? WHERE job_id=? AND lease_id=?`,
						deadline, now, jobID, req.LeaseID); err != nil {
						return err
					}
				}
				if req.Log != nil {
					if err := appendLog(tx, live, *req.Log); err != nil {
						return err
					}
					next := req.Log.Offset + req.Log.Size
					out.LogOffset = &next
				}
			} else if jobID != "" {
				// The lease is no longer live (cancelled, expired, or superseded):
				// tell the runner to stop working on it.
				out.Directives = append(out.Directives, wire.Directive{Kind: wire.DirectiveAbandon, JobID: jobID})
			}
		}
		return nil
	})
	if err != nil {
		return wire.BeatOK{}, &wire.Error{Code: wire.CodeInternal, Message: "heartbeat: " + err.Error()}
	}
	if req.Log != nil {
		d.wakeLeases()
	}
	return out, nil
}

// upsertRunner inserts or updates a fleet row. An empty version preserves the
// existing one (heartbeats don't carry version; hello does).
func upsertRunner(tx *sql.Tx, runnerID string, st wire.HeartbeatStatus, version string, now int64) error {
	lanesJSON, _ := json.Marshal(st.Lanes)
	var vram any
	if st.VRAMFreeMB != nil {
		vram = *st.VRAMFreeMB
	}
	_, err := tx.Exec(
		`INSERT INTO runners(runner_id, node, version, lanes, capacity, gpu, vram_free_mb, last_seen_ts)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(runner_id) DO UPDATE SET
			node=excluded.node,
			version=CASE WHEN excluded.version='' THEN runners.version ELSE excluded.version END,
			lanes=excluded.lanes,
			capacity=excluded.capacity,
			gpu=excluded.gpu,
			vram_free_mb=excluded.vram_free_mb,
			last_seen_ts=excluded.last_seen_ts`,
		runnerID, st.Node, version, string(lanesJSON), st.Capacity, nullStr(st.GPU), vram, now)
	return err
}

func runnerDraining(tx *sql.Tx, runnerID string) (bool, error) {
	var v int
	err := tx.QueryRow(`SELECT draining FROM runners WHERE runner_id=?`, runnerID).Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// jobIDForLease resolves the job a lease was granted for, via the attempt
// timeline (durable even after the lease is voided).
func jobIDForLease(tx *sql.Tx, leaseID string) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT job_id FROM attempts WHERE lease_id=? ORDER BY id LIMIT 1`, leaseID).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}
