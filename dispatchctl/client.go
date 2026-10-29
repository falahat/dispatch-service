package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// client is a small synchronous framed client over one net.Conn. The app
// surface needs no hello/auth, so a call is just: write a request frame, read
// the reply frame. Requests are strictly sequential (one in flight), so a
// monotonically increasing id is enough to correlate.
type client struct {
	conn net.Conn
	seq  atomic.Uint64
}

// dial connects to an app-surface address. "unix:/path" selects AF_UNIX;
// anything else is treated as a "host:port" TCP address.
func dial(addr string) (*client, error) {
	network, target := parseAddr(addr)
	conn, err := net.DialTimeout(network, target, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &client{conn: conn}, nil
}

// parseAddr splits an address into a net.Dial (network, address) pair. The
// "unix:" prefix picks the Unix domain socket; everything else is TCP.
func parseAddr(addr string) (network, target string) {
	if rest, ok := strings.CutPrefix(addr, "unix:"); ok {
		return "unix", rest
	}
	return "tcp", addr
}

func (c *client) close() error { return c.conn.Close() }

// call writes one typed request and reads the single reply, echoing a fresh id.
// A reply of type "error" is surfaced as a *wire.Error (which implements error),
// so callers can branch on the protocol error without re-decoding.
func (c *client) call(typ string, body any) (wire.Envelope, error) {
	id := "c" + strconv.FormatUint(c.seq.Add(1), 10)
	if err := wire.WriteMessage(c.conn, id, typ, body); err != nil {
		return wire.Envelope{}, fmt.Errorf("write %s: %w", typ, err)
	}
	env, err := wire.ReadMessage(c.conn)
	if err != nil {
		return wire.Envelope{}, fmt.Errorf("read reply to %s: %w", typ, err)
	}
	if env.ID != id {
		return env, fmt.Errorf("reply ID differs from request")
	}
	if env.Type == wire.TypeError {
		e, derr := wire.DecodeBody[wire.Error](env)
		if derr != nil {
			return env, fmt.Errorf("decode error reply: %w", derr)
		}
		return env, e
	}
	return env, nil
}
