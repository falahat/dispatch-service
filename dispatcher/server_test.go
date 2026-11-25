package dispatcher

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
)

// framedConn is a minimal test client for the framed wire protocol.
type framedConn struct {
	t    *testing.T
	conn net.Conn
}

func dial(t *testing.T, addr string) *framedConn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return &framedConn{t: t, conn: c}
}

func (f *framedConn) call(id, typ string, body any) wire.Envelope {
	f.t.Helper()
	if err := wire.WriteMessage(f.conn, id, typ, body); err != nil {
		f.t.Fatalf("write %s: %v", typ, err)
	}
	f.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	env, err := wire.ReadMessage(f.conn)
	if err != nil {
		f.t.Fatalf("read reply to %s: %v", typ, err)
	}
	return env
}

func (f *framedConn) read() wire.Envelope {
	f.t.Helper()
	f.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	env, err := wire.ReadMessage(f.conn)
	if err != nil {
		f.t.Fatalf("read: %v", err)
	}
	return env
}

func startTestServer(t *testing.T) *Server {
	t.Helper()
	return startTestServerWith(t, testConfig())
}

func startTestServerWith(t *testing.T, cfg Config) *Server {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg.RunnerListen = "127.0.0.1:0"
	cfg.AppSocket = ""
	cfg.AppListen = "127.0.0.1:0"
	d, err := New(store, cfg, RealClock, nil)
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	srv := NewServer(d, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// TestServerFullFlow drives enqueue -> hello -> lease -> complete -> subscribe
// push -> ack over the real framed protocol on live sockets.
func TestServerFullFlow(t *testing.T) {
	srv := startTestServer(t)
	inv := invAddr("srv-job")

	// App: enqueue.
	app := dial(t, srv.AppAddr())
	env := app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "srv-k", Lane: "embed", InvocationAddress: inv},
	}})
	if env.Type != wire.TypeEnqueueResult {
		t.Fatalf("enqueue reply type %s", env.Type)
	}
	er, err := wire.DecodeBody[wire.EnqueueResult](env)
	if err != nil || len(er.Results) != 1 || !er.Results[0].Created {
		t.Fatalf("enqueue result: %+v err=%v", er, err)
	}
	jobID := er.Results[0].JobID

	// App: subscribe on a dedicated connection BEFORE the completion.
	sub := dial(t, srv.AppAddr())
	if err := wire.WriteMessage(sub.conn, "s1", wire.TypeSubscribe, wire.Subscribe{}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Runner: hello -> lease -> complete.
	run := dial(t, srv.RunnerAddr())
	hres := run.call("h1", wire.TypeHello, wire.Hello{Contract: wire.ContractVersion, Runner: wire.RunnerIdent{ID: "RSRV", Version: "t", Node: "n", Lanes: []string{"embed"}, Capacity: 1}})
	if hres.Type != wire.TypeHelloOK {
		t.Fatalf("hello reply %s", hres.Type)
	}
	gres := run.call("l1", wire.TypeLease, wire.Lease{Lanes: []string{"embed"}, WaitS: 2})
	if gres.Type != wire.TypeGrant {
		t.Fatalf("lease reply %s (%s)", gres.Type, string(gres.Body))
	}
	grant, _ := wire.DecodeBody[wire.Grant](gres)
	if grant.Job.JobID != jobID {
		t.Fatalf("granted %s want %s", grant.Job.JobID, jobID)
	}
	cres := run.call("c1", wire.TypeComplete, wire.Complete{
		LeaseID: grant.Lease.LeaseID, JobID: jobID, Attempt: 1, ActionResult: sampleResult(inv),
	})
	if cres.Type != wire.TypeOK {
		t.Fatalf("complete reply %s (%s)", cres.Type, string(cres.Body))
	}

	// Subscription receives the pushed completion.
	cenv := sub.read()
	if cenv.Type != wire.TypeCompletion {
		t.Fatalf("subscription got %s (%s)", cenv.Type, string(cenv.Body))
	}
	comp, _ := wire.DecodeBody[wire.Completion](cenv)
	if comp.JobID != jobID {
		t.Fatalf("completion job %s want %s", comp.JobID, jobID)
	}
	if comp.ActionResult.InvocationAddress != inv {
		t.Fatalf("completion invocation mismatch")
	}

	// Ack on a separate connection.
	ackc := dial(t, srv.AppAddr())
	ares := ackc.call("a1", wire.TypeAck, wire.Ack{JobID: jobID, Disposition: wire.DispositionPersisted})
	if ares.Type != wire.TypeOK {
		t.Fatalf("ack reply %s (%s)", ares.Type, string(ares.Body))
	}

	// Verify terminal state.
	job, _ := srv.d.GetJob(jobID)
	if job.State != "SUCCEEDED" {
		t.Fatalf("final state %s want SUCCEEDED", job.State)
	}
	_ = artifact.Address("")
}

// TestSubscriptionTakeover verifies newest-connection-wins.
func TestSubscriptionTakeover(t *testing.T) {
	srv := startTestServer(t)

	sub1 := dial(t, srv.AppAddr())
	if err := wire.WriteMessage(sub1.conn, "s1", wire.TypeSubscribe, wire.Subscribe{}); err != nil {
		t.Fatalf("subscribe1: %v", err)
	}
	// Give the server a moment to register sub1.
	time.Sleep(50 * time.Millisecond)

	sub2 := dial(t, srv.AppAddr())
	if err := wire.WriteMessage(sub2.conn, "s2", wire.TypeSubscribe, wire.Subscribe{}); err != nil {
		t.Fatalf("subscribe2: %v", err)
	}

	// sub1 should receive a takeover frame.
	env := sub1.read()
	if env.Type != wire.TypeTakeover {
		t.Fatalf("expected takeover on sub1, got %s", env.Type)
	}
}

// TestALeaseWaitEndsWithItsConnection: a runner that leaves mid long-poll (stopped, or its
// PEP was) is granted nothing, so a job enqueued after it left stays queued for a runner
// that is there.
func TestALeaseWaitEndsWithItsConnection(t *testing.T) {
	cfg := testConfig()
	cfg.MaxWaitS = 30
	srv := startTestServerWith(t, cfg)
	run := runnerHello(t, srv, "RGONE")
	if err := wire.WriteMessage(run.conn, "l1", wire.TypeLease, wire.Lease{Lanes: []string{"embed"}, WaitS: 30}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // the lease waits: nothing is queued
	run.conn.Close()
	waitUntilClosed(t, srv)

	jobID := enqueueOne(t, srv.d, "gone-k", "embed", invAddr("gone"), nil)
	time.Sleep(2 * pollInterval) // a lease still waiting would have claimed it by now
	job, err := srv.d.GetJob(jobID)
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if job.State != "QUEUED" {
		t.Fatalf("job is %s: it went to a runner that had left", job.State)
	}
}

// TestAGrantItsRunnerNeverReceivedIsUndone: a runner asks for a lease while work is queued
// and leaves at once, before the grant can reach it. The dispatcher claims the job as the
// runner goes, or sees it go first. Either way the job must be QUEUED again on the same
// attempt and release count, with no attempt row for a claim that reached no one, and the
// next runner must get it at once rather than after the lease TTL.
func TestAGrantItsRunnerNeverReceivedIsUndone(t *testing.T) {
	cfg := testConfig()
	cfg.MaxWaitS = 30
	srv := startTestServerWith(t, cfg)
	jobID := enqueueOne(t, srv.d, "gone-k", "embed", invAddr("gone"), nil)
	before, err := srv.d.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}

	gone := runnerHello(t, srv, "RGONE")
	if err := wire.WriteMessage(gone.conn, "l1", wire.TypeLease, wire.Lease{Lanes: []string{"embed"}, WaitS: 30}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	gone.conn.Close()
	waitUntilClosed(t, srv)

	job, err := srv.d.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "QUEUED" || job.Attempt != before.Attempt || job.ReleaseCount != before.ReleaseCount || job.LeaseID != "" {
		t.Fatalf("after its runner left: %s, attempt %d, %d releases, lease %q; want QUEUED, attempt %d, %d releases, no lease",
			job.State, job.Attempt, job.ReleaseCount, job.LeaseID, before.Attempt, before.ReleaseCount)
	}
	timeline, err := srv.d.timeline(jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range timeline {
		if a.Outcome == "claimed" {
			t.Fatalf("the timeline keeps a claim that reached no one: %+v", timeline)
		}
	}

	next := runnerHello(t, srv, "RNEXT")
	env := next.call("l2", wire.TypeLease, wire.Lease{Lanes: []string{"embed"}, WaitS: 0})
	grant, err := wire.DecodeBody[wire.Grant](env)
	if env.Type != wire.TypeGrant || err != nil || grant.Job.JobID != jobID || grant.Job.Attempt != before.Attempt {
		t.Fatalf("the next runner's lease: %s %s; want the job on attempt %d", env.Type, env.Body, before.Attempt)
	}
}

// failingListener fails every accept, as a listener does while its process is out of
// file descriptors.
type failingListener struct {
	net.Listener
	accepts atomic.Int64
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	return nil, errors.New("accept: too many open files")
}

// TestAFailingAcceptPausesBeforeTryingAgain: out of file descriptors, every accept fails at
// once until a connection closes. A surface that tried again at once would spin and log
// every failure; it must pause between tries, and still stop when the server does.
func TestAFailingAcceptPausesBeforeTryingAgain(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, log: slog.New(slog.DiscardHandler)}
	ln := &failingListener{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.accept(ln, nil)
	}()
	time.Sleep(1500 * time.Millisecond)
	tries := ln.accepts.Load()
	stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the accept loop did not stop with its server")
	}
	if tries > 3 {
		t.Fatalf("%d accepts in 1.5 s while every accept fails, want at most 3", tries)
	}
}

// runnerHello connects to the runner surface and says hello as runner id.
func runnerHello(t *testing.T, srv *Server, id string) *framedConn {
	t.Helper()
	run := dial(t, srv.RunnerAddr())
	env := run.call("h-"+id, wire.TypeHello, wire.Hello{Contract: wire.ContractVersion, Runner: wire.RunnerIdent{ID: id, Version: "t", Node: "n", Lanes: []string{"embed"}, Capacity: 1}})
	if env.Type != wire.TypeHelloOK {
		t.Fatalf("hello %s: %s %s", id, env.Type, env.Body)
	}
	return run
}

// waitUntilClosed waits up to 2 s for the server to finish with every connection.
func waitUntilClosed(t *testing.T, srv *Server) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		srv.mu.Lock()
		open := len(srv.conns)
		srv.mu.Unlock()
		if open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server still holds %d connections", open)
		}
	}
}

// TestRunnerHelloRequired ensures a non-hello first frame is rejected.
func TestRunnerHelloRequired(t *testing.T) {
	srv := startTestServer(t)
	run := dial(t, srv.RunnerAddr())
	env := run.call("x1", wire.TypeLease, wire.Lease{Lanes: []string{"embed"}, WaitS: 0})
	if env.Type != wire.TypeError {
		t.Fatalf("expected error for pre-hello lease, got %s", env.Type)
	}
}
