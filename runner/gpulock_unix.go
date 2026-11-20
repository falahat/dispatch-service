//go:build linux || darwin

package runner

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// takeGPULock follows the machine's GPU contract shared with other schedulers
// (tailworker): take PATH.want, then PATH, let go of PATH.want, and hold PATH
// until the returned function runs. Holding PATH.want tells a resident server
// to free the GPU. It polls, so a cancelled job stops waiting.
func takeGPULock(ctx context.Context, path string) (func(), error) {
	want, err := flockPolling(ctx, path+".want")
	if err != nil {
		return nil, err
	}
	defer want.Close()
	held, err := flockPolling(ctx, path)
	if err != nil {
		return nil, err
	}
	return func() { held.Close() }, nil
}

func flockPolling(ctx context.Context, path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
