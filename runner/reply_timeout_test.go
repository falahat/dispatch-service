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
		t.Fatalf("%s still waits for its reply after %v", what, replyTimeout+5*time.Second)
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
