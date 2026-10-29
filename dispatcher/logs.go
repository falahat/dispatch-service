package dispatcher

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/falahat/dispatch-service/internal/wire"
)

type logsRequest struct {
	JobID string `json:"job_id"`
	After int64  `json:"after"`
	Wait  bool   `json:"wait"`
}

type logsResult struct {
	Entries    []wire.LogChunk `json:"entries"`
	NextOffset int64           `json:"next_offset"`
	Done       bool            `json:"done"`
}

func appendLog(tx *sql.Tx, job Job, chunk wire.LogChunk) error {
	var end int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(offset+size),0) FROM job_logs WHERE job_id=?`, job.JobID).Scan(&end); err != nil {
		return err
	}
	if chunk.Offset < end {
		var address string
		var size int64
		err := tx.QueryRow(`SELECT address,size FROM job_logs WHERE job_id=? AND offset=?`, job.JobID, chunk.Offset).Scan(&address, &size)
		if err != nil || address != string(chunk.Address) || size != chunk.Size {
			return fmt.Errorf("divergent log chunk")
		}
		return nil
	}
	if chunk.Offset != end {
		return fmt.Errorf("log chunk leaves a gap")
	}
	_, err := tx.Exec(`INSERT INTO job_logs VALUES(?,?,?,?)`, job.JobID, chunk.Offset, string(chunk.Address), chunk.Size)
	return err
}

func (d *Dispatcher) logs(ctx context.Context, request logsRequest) (logsResult, *wire.Error) {
	result := logsResult{Entries: []wire.LogChunk{}, NextOffset: request.After}
	if !jobIDRe.MatchString(request.JobID) || request.After < 0 {
		return result, &wire.Error{Code: wire.CodeInvalid, Message: "invalid log identity or cursor"}
	}
	for {
		wake := d.leaseWake.wait()
		job, err := d.GetJob(request.JobID)
		if err != nil {
			code := wire.CodeInternal
			if err == sql.ErrNoRows {
				code = wire.CodeGone
			}
			return result, &wire.Error{Code: code, Message: "read log job: " + err.Error()}
		}
		if request.After != 0 {
			var exists int
			if err := d.store.db.QueryRow(`SELECT COUNT(*) FROM job_logs WHERE job_id=? AND offset+size=?`, request.JobID, request.After).Scan(&exists); err != nil {
				return result, &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
			}
			if exists == 0 {
				return result, &wire.Error{Code: wire.CodeInvalid, Message: "unknown log cursor"}
			}
		}
		rows, err := d.store.db.Query(`SELECT offset,address,size FROM job_logs WHERE job_id=? AND offset>=? ORDER BY offset LIMIT 32`, request.JobID, request.After)
		if err != nil {
			return result, &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
		}
		for rows.Next() {
			var chunk wire.LogChunk
			if err = rows.Scan(&chunk.Offset, &chunk.Address, &chunk.Size); err != nil {
				break
			}
			result.Entries = append(result.Entries, chunk)
			result.NextOffset = chunk.Offset + chunk.Size
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return result, &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
		}
		var end int64
		if err := d.store.db.QueryRow(`SELECT COALESCE(MAX(offset+size),0) FROM job_logs WHERE job_id=?`, request.JobID).Scan(&end); err != nil {
			return result, &wire.Error{Code: wire.CodeInternal, Message: err.Error()}
		}
		result.Done = job.State != "QUEUED" && job.State != "RUNNING" && job.State != "AWAITING_APPROVAL" && result.NextOffset >= end
		if len(result.Entries) != 0 || result.Done || !request.Wait {
			return result, nil
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return result, &wire.Error{Code: wire.CodeGone, Message: "dispatcher shutting down"}
		}
	}
}
