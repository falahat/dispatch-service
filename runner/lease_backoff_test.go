package runner_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// A lease the dispatcher refuses, as it refuses lanes the runner's credential does not
// grant, holds the next one back, longer after each refusal: 1 s after the first, 2 s
// after the second. The runner used to reconnect, say hello and ask again at once, as
// fast as the refusals came.
func TestARefusedLeaseBacksOff(t *testing.T) {
	leases := make(chan time.Time, 16)
	addr := startFakeDispatcher(t, func(_ int, env wire.Envelope) (string, any) {
		switch env.Type {
		case wire.TypeHello:
			return wire.TypeHelloOK, wire.HelloOK{HeartbeatIntervalS: 60, MinWaitS: 1, MaxWaitS: 30}
		case wire.TypeLease:
			select {
			case leases <- time.Now():
			default: // a runner asking as fast as it is refused fills the buffer
			}
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

	var asked []time.Time
	for len(asked) < 3 {
		select {
		case at := <-leases:
			asked = append(asked, at)
		case <-time.After(20 * time.Second):
			t.Fatalf("the runner asked for %d leases, then none for 20 s", len(asked))
		}
	}
	for i, want := range []time.Duration{time.Second, 2 * time.Second} {
		if gap := asked[i+1].Sub(asked[i]); gap < want {
			t.Fatalf("lease %d came %v after lease %d was refused, want at least %v", i+2, gap, i+1, want)
		}
	}
}
