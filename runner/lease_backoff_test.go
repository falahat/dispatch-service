package runner_test

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// A lease the dispatcher refuses, as it refuses lanes the runner's credential does not
// grant, holds the next one back, longer after each refusal. The runner used to
// reconnect, say hello and ask again at once, as fast as the refusals came.
func TestARefusedLeaseBacksOff(t *testing.T) {
	var leases atomic.Int64
	addr := startFakeDispatcher(t, func(_ int, env wire.Envelope) (string, any) {
		switch env.Type {
		case wire.TypeHello:
			return wire.TypeHelloOK, wire.HelloOK{HeartbeatIntervalS: 60, MinWaitS: 1, MaxWaitS: 30}
		case wire.TypeLease:
			leases.Add(1)
			return wire.TypeError, wire.Error{Code: wire.CodeForbidden, Message: "lanes not granted"}
		default:
			return wire.TypeBeatOK, wire.BeatOK{}
		}
	})
	casSrv := httptest.NewServer(newStubCAS().handler())
	t.Cleanup(casSrv.Close)
	computeSrv := httptest.NewServer(echoComputeHandler())
	t.Cleanup(computeSrv.Close)
	startEchoRunner(t, addr, casSrv.URL, computeSrv.URL)

	time.Sleep(4 * time.Second)
	if asked := leases.Load(); asked != 3 {
		t.Fatalf("the runner asked for %d leases in 4 s of refusals, want 3: at once, 1 s later and 2 s after that", asked)
	}
}
