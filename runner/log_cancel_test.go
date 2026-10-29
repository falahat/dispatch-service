package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func TestAbandonAppliesBeforeUnacknowledgedLog(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "job"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "job", "invoke.log"), []byte("pending output"), 0600); err != nil {
				t.Fatal(err)
			}
			cas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer cas.Close()
			r := New(Config{RunnerID: "worker", Node: "node", Command: []string{"python3"}, WorkRoot: root, CASBaseURL: cas.URL}, nil, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.setCurrent(&liveJob{jobID: "job", leaseID: "expired-lease", cancel: cancel})
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				envelope, err := wire.ReadMessage(server)
				if err != nil {
					done <- err
					return
				}
				heartbeat, err := wire.DecodeBody[wire.Heartbeat](envelope)
				if err != nil {
					done <- err
					return
				}
				if (heartbeat.Log != nil) != (status == http.StatusOK) {
					done <- os.ErrInvalid
					return
				}
				done <- wire.WriteMessage(server, envelope.ID, wire.TypeBeatOK, wire.BeatOK{
					Directives: []wire.Directive{{Kind: wire.DirectiveAbandon, JobID: "job"}},
				})
			}()
			if err := r.beat(context.Background(), &dispatcherConn{conn: client}); err == nil {
				t.Fatal("missing log acknowledgement must remain an error")
			}
			client.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if ctx.Err() == nil || !r.wasAbandoned("job") {
				t.Fatal("a stale lease must stop its executor even when log acknowledgement is absent")
			}
		})
	}
}
