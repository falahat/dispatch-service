package runner_test

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// The heartbeat beats as often as the hello on its current connection says, so a
// dispatcher restarted with a shorter interval hears the runner that often. The runner
// kept the interval of its first hello for good, beating too seldom for a dispatcher
// that grants nothing to a runner unheard for two of its intervals.
func TestTheHeartbeatBeatsAsItsLatestHelloSays(t *testing.T) {
	reconnected := make(chan struct{})
	var beats atomic.Int64
	addr := startFakeDispatcher(t, func(conn int, env wire.Envelope) (string, any) {
		switch env.Type {
		case wire.TypeHello:
			// The runner's first two connections, work then heartbeat, are told to beat
			// every 3 s; the heartbeat's next one, every second.
			if conn < 3 {
				return wire.TypeHelloOK, wire.HelloOK{HeartbeatIntervalS: 3, MinWaitS: 1, MaxWaitS: 30}
			}
			if conn == 3 {
				close(reconnected)
			}
			return wire.TypeHelloOK, wire.HelloOK{HeartbeatIntervalS: 1, MinWaitS: 1, MaxWaitS: 30}
		case wire.TypeHeartbeat:
			if conn == 2 {
				return "", nil // the heartbeat's first connection drops, as a restart drops it
			}
			beats.Add(1)
			return wire.TypeBeatOK, wire.BeatOK{}
		case wire.TypeLease:
			wait := 60
			return wire.TypeEmpty, wire.Empty{RetryAfterS: &wait}
		}
		return "", nil
	})
	casSrv := httptest.NewServer(newStubCAS().handler())
	t.Cleanup(casSrv.Close)
	computeSrv := httptest.NewServer(echoComputeHandler())
	t.Cleanup(computeSrv.Close)
	startEchoRunner(t, addr, casSrv.URL, computeSrv.URL)

	select {
	case <-reconnected:
	case <-time.After(20 * time.Second):
		t.Fatal("the heartbeat never reconnected")
	}
	time.Sleep(4500 * time.Millisecond)
	if beat := beats.Load(); beat < 3 {
		t.Fatalf("the heartbeat beat %d times in 4.5 s on a connection whose hello said every second", beat)
	}
}
