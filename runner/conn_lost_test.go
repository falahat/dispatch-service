package runner_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// cutProxy relays connections to a target until cut, which drops every connection
// it carries at once, as a PEP or dispatcher restart does.
type cutProxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startCutProxy(t *testing.T, target string) *cutProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cutProxy{ln: ln}
	go p.serve(target)
	t.Cleanup(func() {
		ln.Close()
		p.cut()
	})
	return p
}

func (p *cutProxy) addr() string { return p.ln.Addr().String() }

func (p *cutProxy) serve(target string) {
	for {
		down, err := p.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", target)
		if err != nil {
			down.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, down, up)
		p.mu.Unlock()
		go relay(up, down)
		go relay(down, up)
	}
}

func relay(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	dst.Close()
	src.Close()
}

func (p *cutProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
}

// gatedCompute is the echo compute holding every invoke until opened. started
// receives once an invoke has arrived.
func gatedCompute(t *testing.T) (url string, started <-chan struct{}, open func()) {
	t.Helper()
	echo := echoComputeHandler()
	arrived := make(chan struct{}, 1)
	gate := make(chan struct{})
	var once sync.Once
	opened := func() { once.Do(func() { close(gate) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/invoke" {
			select {
			case arrived <- struct{}{}:
			default:
			}
			<-gate
		}
		echo.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(opened) // runs first, so Close does not wait on a held invoke
	return srv.URL, arrived, opened
}

func waitForInvoke(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("the job never reached its compute")
	}
}

func waitForState(t *testing.T, app *appClient, jobID, state string) wire.JobView {
	t.Helper()
	var view wire.JobView
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if view = jobView(t, app, jobID); view.State == state {
			return view
		}
	}
	t.Fatalf("job never reached %s: %+v", state, view)
	return view
}

// A job whose connection to the dispatcher died while it ran reports its result
// over a new one. A PEP or dispatcher restart drops every runner connection while
// the lease lives on. The result used to go out on the dead connection and be lost,
// and the job sat RUNNING until its lease expired, then ran again on a new attempt.
func TestAJobReportsItsResultAfterItsConnectionDied(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	computeURL, started, open := gatedCompute(t)
	proxy := startCutProxy(t, srv.RunnerAddr())
	startEchoRunner(t, proxy.addr(), casSrv.URL, computeURL)
	app := dialApp(t, srv.AppAddr())
	jobID := enqueueEcho(t, app, cas, "lost-k")

	waitForInvoke(t, started)
	before := jobView(t, app, jobID)
	proxy.cut()
	open()

	after := waitForState(t, app, jobID, "PERSISTING")
	if after.Attempt != before.Attempt || after.ReleaseCount != 0 {
		t.Fatalf("the job ran again (attempt %d, %d releases); it started on attempt %d",
			after.Attempt, after.ReleaseCount, before.Attempt)
	}
}

// A job refused its upload after its connection died is released over a new
// connection and runs again at once, on the same attempt. A restarted PEP refuses
// a running job's uploads, because its lease book starts empty and learns a lease
// only from the grant. The release used to be lost with the old connection, so the
// job waited out its lease instead.
func TestAJobRefusedItsUploadAfterItsConnectionDiedRunsAgainAtOnce(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	store := cas.handler()
	var refuse atomic.Bool
	casSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			http.Error(w, "not_in_lease", http.StatusForbidden)
			return
		}
		store.ServeHTTP(w, r)
	}))
	defer casSrv.Close()
	computeURL, started, open := gatedCompute(t)
	proxy := startCutProxy(t, srv.RunnerAddr())
	startEchoRunner(t, proxy.addr(), casSrv.URL, computeURL)
	app := dialApp(t, srv.AppAddr())
	jobID := enqueueEcho(t, app, cas, "refused-k")

	waitForInvoke(t, started)
	before := jobView(t, app, jobID)
	refuse.Store(true)
	proxy.cut()
	open()

	// The restarted PEP refuses the job until it is granted again.
	for deadline := time.Now().Add(20 * time.Second); jobView(t, app, jobID).ReleaseCount == 0; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the job was never released: %+v", jobView(t, app, jobID))
		}
	}
	refuse.Store(false)

	after := waitForState(t, app, jobID, "PERSISTING")
	if after.Attempt != before.Attempt {
		t.Fatalf("the job ran again on attempt %d; it started on %d", after.Attempt, before.Attempt)
	}
}
