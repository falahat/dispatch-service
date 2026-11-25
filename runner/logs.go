package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/falahat/dispatch-service/internal/wire"
)

// logChunk returns the piece of the command's log the next heartbeat ships. A chunk
// shipped before and not yet acknowledged goes again exactly as it was: the
// dispatcher may have stored it before its reply was lost, and takes nothing else at
// that offset. Otherwise it is the next bytes of invoke.log, at most 1 MiB, placed
// after the log the job's earlier attempts shipped.
func (r *Runner) logChunk(ctx context.Context) (*wire.LogChunk, error) {
	if len(r.cfg.Command) == 0 {
		return nil, nil
	}
	r.mu.Lock()
	job := r.current
	var current liveJob
	if job != nil {
		current = *job
	}
	r.mu.Unlock()
	if job == nil {
		return nil, nil
	}
	if current.logSent != nil {
		return current.logSent, nil
	}
	file, err := os.Open(filepath.Join(r.cfg.WorkRoot, current.jobID, "invoke.log"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	shipped := current.logOffset - current.logBase
	if shipped > info.Size() {
		return nil, fmt.Errorf("command log truncated")
	}
	if _, err := file.Seek(shipped, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil || len(data) == 0 {
		return nil, err
	}
	address, err := r.cas.PutBytes(ctx, data)
	if err != nil {
		return nil, err
	}
	chunk := &wire.LogChunk{Offset: current.logOffset, Address: address, Size: int64(len(data))}
	r.mu.Lock()
	job.logSent = chunk
	r.mu.Unlock()
	return chunk, nil
}

// flushLog ships the rest of the command's log ahead of its job's result or
// failure. Each beat must move the acknowledged end forward: one the dispatcher
// refused ends the flush with an error instead of sending the chunk again at once. A
// beat that failed, its reply late or its connection dead, goes once more over a new
// connection: the dispatcher takes the same chunk at the same offset again.
func (r *Runner) flushLog(ctx context.Context, dc *dispatcherConn) error {
	if len(r.cfg.Command) == 0 {
		return nil
	}
	resent := false
	for {
		r.mu.Lock()
		job := *r.current
		r.mu.Unlock()
		info, err := os.Stat(filepath.Join(r.cfg.WorkRoot, job.jobID, "invoke.log"))
		if err != nil || job.logOffset-job.logBase >= info.Size() {
			return err
		}
		if err := r.beat(ctx, dc); err != nil {
			if resent || r.reconnect(ctx, dc) != nil {
				return err
			}
			resent = true
			continue
		}
		resent = false
		r.mu.Lock()
		advanced := r.current.logOffset > job.logOffset
		r.mu.Unlock()
		if !advanced {
			return errors.New("the dispatcher did not take the command log")
		}
	}
}
