package runner_test

import (
	"net"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

// answerFunc scripts a fake dispatcher's reply to one frame. conn numbers the runner's
// connections from 1 in the order it made them. An empty reply type closes the
// connection without a reply. It is called from one goroutine per connection.
type answerFunc func(conn int, env wire.Envelope) (typ string, body any)

// startFakeDispatcher serves the runner side of the wire as answer scripts it, so a test
// can give replies a real dispatcher would not, and returns its address.
func startFakeDispatcher(t *testing.T, answer answerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for n := 1; ; n++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveScripted(conn, n, answer)
		}
	}()
	return ln.Addr().String()
}

func serveScripted(conn net.Conn, n int, answer answerFunc) {
	defer conn.Close()
	for {
		env, err := wire.ReadMessage(conn)
		if err != nil {
			return
		}
		typ, body := answer(n, env)
		if typ == "" || wire.WriteMessage(conn, env.ID, typ, body) != nil {
			return
		}
	}
}
