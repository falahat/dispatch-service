package runner_test

import (
	"io"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/wire"
)

// leaseCounter relays a runner's connections to the dispatcher and counts the lease
// frames the runner sends.
type leaseCounter struct {
	ln     net.Listener
	leases atomic.Int64
}

func startLeaseCounter(t *testing.T, target string) *leaseCounter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &leaseCounter{ln: ln}
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
			go c.countLeases(down, up)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *leaseCounter) countLeases(down, up net.Conn) {
	defer up.Close()
	for {
		frame, err := wire.ReadFrame(down)
		if err != nil {
			return
		}
		if env, err := wire.DecodeEnvelope(frame); err == nil && env.Type == wire.TypeLease {
			c.leases.Add(1)
		}
		if err := wire.WriteFrame(up, frame); err != nil {
			return
		}
	}
}

// An empty lease that names retry_after_s holds the runner's next lease back that long.
// The dispatcher answers at once while the runner's lanes are in backpressure, so a
// runner that asked again at once spun, sending frame after frame through the PEP for
// as long as the app took to catch up.
func TestARunnerWaitsTheRetryAfterAnEmptyLeaseNames(t *testing.T) {
	srv := startDispatcher(t, func(c *dispatcher.Config) {
		c.Lanes = map[string]dispatcher.LaneConfig{"embed": {Concurrency: 4, PersistingWatermark: 1}}
	})
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	computeSrv := httptest.NewServer(echoComputeHandler())
	defer computeSrv.Close()
	counter := startLeaseCounter(t, srv.RunnerAddr())
	startEchoRunner(t, counter.ln.Addr().String(), casSrv.URL, computeSrv.URL)

	// Two results the app never acks put the lane over its watermark of one.
	app := dialApp(t, srv.AppAddr())
	first, second := enqueueEcho(t, app, cas, "bp-1"), enqueueEcho(t, app, cas, "bp-2")
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if jobView(t, app, first).State == "PERSISTING" && jobView(t, app, second).State == "PERSISTING" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the jobs never finished: %+v, %+v", jobView(t, app, first), jobView(t, app, second))
		}
	}

	counter.leases.Store(0)
	time.Sleep(3 * time.Second)
	if asked := counter.leases.Load(); asked > 3 {
		t.Fatalf("the runner asked for %d leases in 3 s of backpressure, whose empty answers say to wait 2 s", asked)
	}
}
