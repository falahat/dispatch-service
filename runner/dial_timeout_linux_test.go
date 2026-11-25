//go:build linux

package runner

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

// A connect that is never answered fails, so a heartbeat loop that reconnects cannot hang
// on it for the minutes the kernel would give it. A listener whose accept queue is full
// drops each new connection attempt without a word, as a relay in front of the PEP may.
func TestAConnectNeverAnsweredFails(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var shrunk error
	if err := raw.Control(func(fd uintptr) { shrunk = syscall.Listen(int(fd), 0) }); err != nil || shrunk != nil {
		t.Fatalf("shrink the accept queue: %v %v", err, shrunk)
	}
	// The one connection a queue of no backlog holds. Nothing accepts it, so the queue
	// stays full.
	held, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ident := wire.RunnerIdent{ID: "worker", Node: "node", Lanes: []string{"embed"}, Capacity: 1}
	failsWithinTheReplyTimeout(t, "a connect", func() error {
		_, _, err := dialDispatcher(context.Background(), ln.Addr().String(), ident, nil)
		return err
	})
}
