package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/falahat/dispatch-service/internal/wire"
)

func (r *Runner) logChunk(ctx context.Context) (*wire.LogChunk, error) {
	if len(r.cfg.Command) == 0 {
		return nil, nil
	}
	r.mu.Lock()
	job := r.current
	var id string
	var offset int64
	if job != nil {
		id, offset = job.jobID, job.logOffset
	}
	r.mu.Unlock()
	if job == nil {
		return nil, nil
	}
	file, err := os.Open(filepath.Join(r.cfg.WorkRoot, id, "invoke.log"))
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
	if offset > info.Size() {
		return nil, fmt.Errorf("command log truncated")
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
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
	return &wire.LogChunk{Offset: offset, Address: address, Size: int64(len(data))}, nil
}

func (r *Runner) flushLog(ctx context.Context, dc *dispatcherConn) error {
	if len(r.cfg.Command) == 0 {
		return nil
	}
	for {
		r.mu.Lock()
		job := *r.current
		r.mu.Unlock()
		info, err := os.Stat(filepath.Join(r.cfg.WorkRoot, job.jobID, "invoke.log"))
		if err != nil || job.logOffset >= info.Size() {
			return err
		}
		if err := r.beat(ctx, dc); err != nil {
			return err
		}
	}
}
