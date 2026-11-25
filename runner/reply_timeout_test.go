package runner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// swallow reads every frame that arrives on conn and answers none, like a relay that
// holds a connection open with no one answering behind it.
func swallow(conn net.Conn) {
	defer conn.Close()
	for {
		if _, err := wire.ReadFrame(conn); err != nil {
			return
		}
	}
}

// failsWithinTheReplyTimeout fails the test unless call returns an error once the reply
// timeout has passed, and not long after.
func failsWithinTheReplyTimeout(t *testing.T, what string, call func() error) {
	t.Helper()
	done := make(chan error, 1)
	began := time.Now()
	go func() { done <- call() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("%s that was never answered succeeded", what)
		}
		if waited := time.Since(began); waited < replyTimeout-time.Second {
			t.Fatalf("%s gave up after %v, before its %v", what, waited, replyTimeout)
		}
	case <-time.After(replyTimeout + 5*time.Second):
		t.Fatalf("%s still waits after %v", what, replyTimeout+5*time.Second)
	}
}

// A heartbeat whose reply never comes fails, so the heartbeat loop replaces its
// connection. The heartbeat is the runner's sign of life (D20): stuck on a reply, a
// runner that is still there would go unheard, and be granted nothing.
func TestAHeartbeatWithNoReplyFails(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	go swallow(server)
	r := New(Config{RunnerID: "worker", Node: "node"}, nil, nil, nil)
	failsWithinTheReplyTimeout(t, "a heartbeat", func() error {
		return r.beat(context.Background(), &dispatcherConn{conn: client})
	})
}

// A hello whose reply never comes fails too, so a heartbeat loop that reconnects cannot
// hang on the new connection instead.
func TestAHelloWithNoReplyFails(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go swallow(conn)
		}
	}()
	ident := wire.RunnerIdent{ID: "worker", Node: "node", Lanes: []string{"embed"}, Capacity: 1}
	failsWithinTheReplyTimeout(t, "a hello", func() error {
		_, _, err := dialDispatcher(context.Background(), ln.Addr().String(), ident, nil)
		return err
	})
}

// nowhere returns an address no one listens on.
func nowhere(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// A job's report whose reply never comes fails too, so a work connection held open with
// no one answering cannot stall the runner's work for good.
func TestAReportWithNoReplyFails(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	go swallow(server)
	r := New(Config{RunnerID: "worker", Node: "node", DispatcherAddr: nowhere(t)}, nil, nil, nil)
	failsWithinTheReplyTimeout(t, "a report", func() error {
		_, err := r.send(context.Background(), &dispatcherConn{conn: client}, wire.TypeComplete, wire.Complete{JobID: "job"})
		return err
	})
}

// A reply that comes after its request gave up on it never answers the next request:
// the call that gave up closed its connection.
func TestALateReplyNeverAnswersTheNextRequest(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		late, err := wire.ReadMessage(conn)
		if err != nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
		_ = wire.WriteMessage(conn, late.ID, wire.TypeBeatOK, wire.BeatOK{Directives: []wire.Directive{}})
		for {
			env, err := wire.ReadMessage(conn)
			if err != nil {
				return
			}
			_ = wire.WriteMessage(conn, env.ID, wire.TypeOK, struct{}{})
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dc := &dispatcherConn{conn: conn}
	defer dc.close()
	if _, err := dc.call(wire.TypeHeartbeat, wire.Heartbeat{}, 100*time.Millisecond); err == nil {
		t.Fatal("a heartbeat whose reply came late succeeded")
	}
	time.Sleep(400 * time.Millisecond) // the late reply has arrived
	if env, err := dc.call(wire.TypeRelease, wire.Release{JobID: "job"}, time.Second); err == nil {
		t.Fatalf("a release took %s %s, the late reply to an earlier request, as its own", env.Type, env.ID)
	}
}
