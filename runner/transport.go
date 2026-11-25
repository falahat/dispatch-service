package runner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// FrameWrapper wraps an outgoing runner frame with auth (Biscuit + PoP) for the
// PEP. In direct/trusted mode it is nil and frames are sent verbatim. The reply
// is always a plain wire frame (the dispatcher's response, forwarded by the PEP).
type FrameWrapper interface {
	Wrap(typ string, inner []byte) ([]byte, error)
}

// dispatcherConn is a framed request/reply channel to the dispatcher runner
// surface (direct, or via the PEP when wrapper != nil). One connection is a
// strictly sequential channel; the caller must not overlap calls on it.
type dispatcherConn struct {
	conn    net.Conn
	wrapper FrameWrapper
	mu      sync.Mutex
	seq     atomic.Uint64
}

// replyTimeout bounds a connect to the dispatcher and the wait for the reply to a hello
// or a heartbeat. The dispatcher answers both at once, so a reply that has not come by
// then is not coming, and the connection is taken for dead; a connect that a relay drops
// without a word would otherwise wait out the kernel's retries, about 127 s on Linux. The
// heartbeat is the runner's sign of life (D20): a heartbeat connection stuck on a connect
// or a reply would leave a runner that is still there unheard, and granted nothing, for
// as long as it stayed stuck: minutes on a dead path, for good where a relay holds it open.
const replyTimeout = 10 * time.Second

// dialDispatcher connects and performs the hello handshake, returning the
// server parameters (heartbeat interval, wait bounds).
func dialDispatcher(ctx context.Context, addr string, ident wire.RunnerIdent, wrapper FrameWrapper) (*dispatcherConn, wire.HelloOK, error) {
	d := net.Dialer{Timeout: replyTimeout}
	network := "tcp"
	if strings.HasPrefix(addr, "unix:") {
		network, addr = "unix", strings.TrimPrefix(addr, "unix:")
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, wire.HelloOK{}, fmt.Errorf("dial dispatcher %s: %w", addr, err)
	}
	dc := &dispatcherConn{conn: conn, wrapper: wrapper}
	dc.setReadTimeout(replyTimeout)
	env, err := dc.call(wire.TypeHello, wire.Hello{Contract: wire.ContractVersion, Runner: ident})
	dc.setReadTimeout(0)
	if err != nil {
		conn.Close()
		return nil, wire.HelloOK{}, fmt.Errorf("hello: %w", err)
	}
	if env.Type != wire.TypeHelloOK {
		conn.Close()
		return nil, wire.HelloOK{}, fmt.Errorf("hello rejected: %s %s", env.Type, string(env.Body))
	}
	ok, err := wire.DecodeBody[wire.HelloOK](env)
	if err != nil {
		conn.Close()
		return nil, wire.HelloOK{}, err
	}
	return dc, ok, nil
}

func (dc *dispatcherConn) close() { dc.conn.Close() }

// renew swaps fresh's connection in for dc's dead one, so every holder of dc
// carries on over the live connection.
func (dc *dispatcherConn) renew(fresh *dispatcherConn) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	dc.conn.Close()
	dc.conn = fresh.conn
}

// call sends one framed request and reads its reply. It serializes access to the
// connection.
func (dc *dispatcherConn) call(typ string, body any) (wire.Envelope, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	id := "r" + strconv.FormatUint(dc.seq.Add(1), 10)
	inner, err := wire.MarshalEnvelope(id, typ, body)
	if err != nil {
		return wire.Envelope{}, err
	}
	out := inner
	if dc.wrapper != nil {
		out, err = dc.wrapper.Wrap(typ, inner)
		if err != nil {
			return wire.Envelope{}, err
		}
	}
	if err := wire.WriteFrame(dc.conn, out); err != nil {
		return wire.Envelope{}, err
	}
	env, err := wire.ReadMessage(dc.conn)
	if err != nil {
		return wire.Envelope{}, err
	}
	return env, nil
}

// asError converts an error-typed reply into a *wire.Error.
func asError(env wire.Envelope) *wire.Error {
	if env.Type != wire.TypeError {
		return nil
	}
	e, err := wire.DecodeBody[wire.Error](env)
	if err != nil {
		return &wire.Error{Code: wire.CodeInternal, Message: "undecodable error frame"}
	}
	return &e
}

// setReadTimeout applies a read deadline for a single blocking call (e.g. a
// long-poll lease uses waitS + slack).
func (dc *dispatcherConn) setReadTimeout(d time.Duration) {
	if d <= 0 {
		dc.conn.SetReadDeadline(time.Time{})
		return
	}
	dc.conn.SetReadDeadline(time.Now().Add(d))
}
