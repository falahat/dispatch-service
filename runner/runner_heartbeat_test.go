package runner_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/falahat/dispatch-service/runner"
)

// countingProxy forwards TCP to a backend, counting accepted client connections
// and able to force-close every live connection (dropAll) — to simulate a network
// blip between the runner and the dispatcher.
type countingProxy struct {
	ln       net.Listener
	backend  string
	mu       sync.Mutex
	conns    []net.Conn
	accepted int
}

func newCountingProxy(t *testing.T, backend string) *countingProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &countingProxy{ln: ln, backend: backend}
	go p.serve()
	t.Cleanup(func() { ln.Close(); p.dropAll() })
	return p
}

func (p *countingProxy) addr() string { return p.ln.Addr().String() }

func (p *countingProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		upstream, err := net.Dial("tcp", p.backend)
		if err != nil {
			client.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, client, upstream)
		p.accepted++
		p.mu.Unlock()
		go func() { _, _ = io.Copy(upstream, client) }()
		go func() { _, _ = io.Copy(client, upstream) }()
	}
}

func (p *countingProxy) acceptedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

func (p *countingProxy) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

// blockingComputeHandler serves the invoke protocol but blocks the invoke until
// `release` is closed, signalling `invoked` when the first invoke arrives — so a
// test can hold the work loop inside a single long-running invoke.
func blockingComputeHandler(invoked chan<- struct{}, release <-chan struct{}) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "op": "echo", "op_version": 1})
	})
	var once sync.Once
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		var req runner.InvokeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		once.Do(func() { close(invoked) })
		<-release // hold the work loop inside the invoke
		_ = os.MkdirAll(filepath.Join(req.Workdir, req.OutputsDir), 0o755)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"outputs": map[string]string{}, "metrics": map[string]int64{},
		})
	})
	return mux
}

// TestHeartbeatReconnectsAfterConnectionDrop guards the drain-collapse trigger: if
// the heartbeat connection breaks and the loop does NOT redial, the dispatcher stops
// renewing the lease, the in-flight job is reclaimed mid-run, and the re-lease invokes
// a still-busy compute (409 -> keep-alive desync -> the whole queue fails).
//
// It runs the runner through a proxy, drops every runner<->dispatcher connection while
// the work loop is blocked inside a single invoke, and asserts a NEW connection appears
// — which can only be the heartbeat loop reconnecting (the work loop is parked in the
// invoke and won't redial until it returns). Without the reconnect fix, no new
// connection appears and this times out.
func TestHeartbeatReconnectsAfterConnectionDrop(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()

	invoked := make(chan struct{})
	release := make(chan struct{})
	computeSrv := httptest.NewServer(blockingComputeHandler(invoked, release))
	defer computeSrv.Close()

	inv := artifact.Invocation{Kind: artifact.InvocationKind, Op: "echo", OpVersion: 1, Params: json.RawMessage(`{}`)}
	invBytes, _ := json.Marshal(inv)
	invAddr := cas.put(invBytes)

	app := dialApp(t, srv.AppAddr())
	app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "hb-k", Lane: "embed", InvocationAddress: invAddr},
	}})

	proxy := newCountingProxy(t, srv.RunnerAddr())
	rn := runner.New(runner.Config{
		RunnerID: "Rhb", Node: "n1", Version: "runner/test",
		DispatcherAddr: proxy.addr(),
		CASBaseURL:     casSrv.URL,
		ComputeAddr:    strings.TrimPrefix(computeSrv.URL, "http://"),
		WorkRoot:       t.TempDir(),
		Lanes:          []string{"embed"},
		Capacity:       1,
		LeaseWaitS:     2,
	}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rn.Run(ctx)

	// The runner has connected (work + heartbeat) and is now parked inside the invoke.
	select {
	case <-invoked:
	case <-time.After(15 * time.Second):
		t.Fatal("compute was never invoked")
	}
	before := proxy.acceptedCount()

	// Simulate the blip: kill every runner<->dispatcher connection.
	proxy.dropAll()

	// The heartbeat loop must reconnect so lease renewal resumes. A new proxy
	// connection appearing while the work loop is still parked in the invoke is
	// specifically the heartbeat reconnect.
	reconnected := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if proxy.acceptedCount() > before {
			reconnected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	close(release) // let the job finish regardless, so the runner can shut down cleanly
	if !reconnected {
		t.Fatal("heartbeat did not reconnect after the connection dropped: lease renewal would stall and the drain collapse")
	}
}
