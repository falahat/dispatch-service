package runner_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/falahat/dispatch-service/runner"
)

// logHolder relays a runner's connections to the dispatcher and holds back the first
// heartbeat that carries a log chunk, for hold.
type logHolder struct {
	ln   net.Listener
	hold time.Duration
	held atomic.Bool
}

func startLogHolder(t *testing.T, target string, hold time.Duration) *logHolder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &logHolder{ln: ln, hold: hold}
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				down.Close()
				continue
			}
			go func() {
				_, _ = io.Copy(down, up)
				down.Close()
			}()
			go h.relay(down, up)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return h
}

func (h *logHolder) relay(down, up net.Conn) {
	defer up.Close()
	for {
		frame, err := wire.ReadFrame(down)
		if err != nil {
			return
		}
		if env, err := wire.DecodeEnvelope(frame); err == nil && env.Type == wire.TypeHeartbeat {
			beat, err := wire.DecodeBody[wire.Heartbeat](env)
			if err == nil && beat.Log != nil && h.held.CompareAndSwap(false, true) {
				time.Sleep(h.hold)
			}
		}
		if err := wire.WriteFrame(up, frame); err != nil {
			return
		}
	}
}

// oneLineCommand counts its runs in the runner's state root, prints one line and
// succeeds.
const oneLineCommand = `import json, os, sys
request = json.load(sys.stdin)
with open(os.path.join(request['roots']['state'], 'runs'), 'ab') as runs:
    runs.write(b'run\n')
os.write(1, b'the only log line\n')
json.dump({'outputs': {}, 'metrics': {'exit': 0}}, open('invoke-result.json', 'w'))
`

// A finished command's log flush whose reply comes too late goes once more over a new
// connection, and the job completes on its first run with its whole log. It used to be
// released as shipping, so the finished job ran again.
func TestALateLogFlushKeepsTheFinishedJob(t *testing.T) {
	// The heartbeat loop beats only after a minute, so the flush ahead of the result
	// is what ships the log.
	srv := startDispatcher(t, func(c *dispatcher.Config) { c.HeartbeatIntervalS = 60 })
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	t.Cleanup(casSrv.Close)
	holder := startLogHolder(t, srv.RunnerAddr(), 12*time.Second) // past the runner's 10 s wait
	invBytes, _ := json.Marshal(artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "run", OpVersion: 1, Params: json.RawMessage(`{}`),
		Inputs: map[string]artifact.Input{},
	})
	app := dialApp(t, srv.AppAddr())
	enqueued, err := wire.DecodeBody[wire.EnqueueResult](app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{{
		JobKey: "flushes-late", Lane: "embed", InvocationAddress: cas.put(invBytes),
	}}}))
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	rn := runner.New(runner.Config{
		RunnerID: "Rflush", Node: "n1", Version: "runner/test",
		DispatcherAddr: holder.ln.Addr().String(), CASBaseURL: casSrv.URL,
		Command:  []string{"python3", "-c", oneLineCommand},
		WorkRoot: t.TempDir(), Lanes: []string{"embed"}, Capacity: 1, LeaseWaitS: 2,
		Roots: map[string]string{"state": state}, NoDeadline: true,
	}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go rn.Run(ctx)

	jobID := enqueued.Results[0].JobID
	view := waitForState(t, app, jobID, "PERSISTING")
	if view.Attempt != 1 || view.ReleaseCount != 0 {
		t.Fatalf("job finished on attempt %d after %d releases, want its first run", view.Attempt, view.ReleaseCount)
	}
	if runs, err := os.ReadFile(filepath.Join(state, "runs")); err != nil || string(runs) != "run\n" {
		t.Fatalf("the command ran %q (%v), want once", runs, err)
	}
	page, err := wire.DecodeBody[struct {
		Entries    []wire.LogChunk `json:"entries"`
		NextOffset int64           `json:"next_offset"`
		Done       bool            `json:"done"`
	}](app.call("l1", "logs", map[string]any{"job_id": jobID, "after": 0}))
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	cas.mu.Lock()
	for _, entry := range page.Entries {
		log.Write(cas.blobs[entry.Address.Hex()])
	}
	cas.mu.Unlock()
	if log.String() != "the only log line\n" {
		t.Fatalf("job log = %q, want the command's line once", log.String())
	}
}
