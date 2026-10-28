package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Admin reply types (app surface only; not part of the frozen runner wire).
const (
	typeJobsResult   = "jobs_result"
	typeFleetResult  = "fleet_result"
	typeBudgetResult = "budget_result"
	typeSweepResult  = "sweep_result"
	typeStatsResult  = "stats_result"
)

// Server exposes the dispatcher over two surfaces: the runner surface (framed
// TCP, PEP-fronted in production — the dispatcher trusts the hello-declared
// identity) and the app/admin surface (Unix domain socket, filesystem perms as
// access control; loopback TCP where AF_UNIX is absent).
type Server struct {
	d   *Dispatcher
	cfg Config
	log *slog.Logger

	runnerLn net.Listener
	appLn    net.Listener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewServer builds a server around a dispatcher.
func NewServer(d *Dispatcher, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{d: d, cfg: d.cfg, log: log, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
}

// Start opens the listeners and begins serving. It also starts the sweeper.
func (s *Server) Start() error {
	network, address := "tcp", s.cfg.RunnerListen
	if strings.HasPrefix(address, "unix:") {
		network, address = "unix", strings.TrimPrefix(address, "unix:")
		_ = os.Remove(address)
	}
	rl, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("server: runner listen: %w", err)
	}
	s.runnerLn = rl
	if network == "unix" {
		if err := os.Chmod(address, 0600); err != nil {
			rl.Close()
			return err
		}
	}
	al, err := s.listenApp()
	if err != nil {
		rl.Close()
		return err
	}
	s.appLn = al

	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.d.RunSweeper(s.ctx) }()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.accept(rl, s.handleRunnerConn) }()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.accept(al, s.handleAppConn) }()

	s.log.Info("dispatcher serving", "runner", s.cfg.RunnerListen, "app", s.appAddr())
	return nil
}

// RunnerAddr returns the bound runner-surface address (useful when the config
// requested port 0).
func (s *Server) RunnerAddr() string { return s.runnerLn.Addr().String() }

// AppAddr returns the bound app-surface address.
func (s *Server) AppAddr() string { return s.appLn.Addr().String() }

func (s *Server) appAddr() string {
	if s.cfg.AppSocket != "" {
		return "unix:" + s.cfg.AppSocket
	}
	return s.cfg.AppListen
}

func (s *Server) listenApp() (net.Listener, error) {
	if s.cfg.AppSocket != "" {
		// Remove a stale socket, then restrict to the owner.
		_ = os.Remove(s.cfg.AppSocket)
		ln, err := net.Listen("unix", s.cfg.AppSocket)
		if err != nil {
			return nil, fmt.Errorf("server: app unix listen: %w", err)
		}
		_ = os.Chmod(s.cfg.AppSocket, 0o600)
		return ln, nil
	}
	ln, err := net.Listen("tcp", s.cfg.AppListen)
	if err != nil {
		return nil, fmt.Errorf("server: app tcp listen: %w", err)
	}
	return ln, nil
}

// Close stops the server, unblocking in-flight long-polls and closing all conns.
func (s *Server) Close() error {
	s.cancel()
	if s.runnerLn != nil {
		s.runnerLn.Close()
	}
	if s.appLn != nil {
		s.appLn.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if s.cfg.AppSocket != "" {
		_ = os.Remove(s.cfg.AppSocket)
	}
	return nil
}

func (s *Server) accept(ln net.Listener, handle func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.log.Warn("accept error", "err", err)
				continue
			}
		}
		s.track(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(conn)
			defer conn.Close()
			handle(conn)
		}()
	}
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// reply writes a typed reply echoing the request id.
func reply(conn net.Conn, id, typ string, body any) error {
	return wire.WriteMessage(conn, id, typ, body)
}

func replyErr(conn net.Conn, id string, e *wire.Error) error {
	return wire.WriteMessage(conn, id, wire.TypeError, e)
}

// handleRunnerConn serves one runner connection: hello, then a request loop.
// In production this connection is the PEP's loopback forward for exactly one
// authenticated runner; hello.runner.id is that verified identity.
func (s *Server) handleRunnerConn(conn net.Conn) {
	env, err := wire.ReadMessage(conn)
	if err != nil {
		return
	}
	if env.Type != wire.TypeHello {
		_ = replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: "expected hello first"})
		return
	}
	h, err := wire.DecodeBody[wire.Hello](env)
	if err != nil {
		_ = replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: "hello: " + err.Error()})
		return
	}
	ok, werr := s.d.Hello(h)
	if werr != nil {
		_ = replyErr(conn, env.ID, werr)
		return
	}
	runnerID := h.Runner.ID
	if err := reply(conn, env.ID, wire.TypeHelloOK, ok); err != nil {
		return
	}

	for {
		env, err := wire.ReadMessage(conn)
		if err != nil {
			return
		}
		if err := s.serveRunnerFrame(conn, runnerID, env); err != nil {
			return
		}
	}
}

func (s *Server) serveRunnerFrame(conn net.Conn, runnerID string, env wire.Envelope) error {
	switch env.Type {
	case wire.TypeLease:
		req, err := wire.DecodeBody[wire.Lease](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		grant, empty, werr := s.d.Lease(s.ctx, runnerID, req)
		if werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		if grant != nil {
			return reply(conn, env.ID, wire.TypeGrant, grant)
		}
		return reply(conn, env.ID, wire.TypeEmpty, empty)
	case wire.TypeHeartbeat:
		req, err := wire.DecodeBody[wire.Heartbeat](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		beat, werr := s.d.Heartbeat(runnerID, req)
		if werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeBeatOK, beat)
	case wire.TypeComplete:
		req, err := wire.DecodeBody[wire.Complete](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Complete(runnerID, req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	case wire.TypeFail:
		req, err := wire.DecodeBody[wire.Fail](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Fail(runnerID, req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	case wire.TypeRelease:
		req, err := wire.DecodeBody[wire.Release](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Release(runnerID, req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	default:
		return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: "unknown runner verb " + env.Type})
	}
}

// --- app surface ---

type jobsFilterWire struct {
	State        string `json:"state,omitempty"`
	Lane         string `json:"lane,omitempty"`
	JobKeyPrefix string `json:"job_key_prefix,omitempty"`
}

type jobsRequest struct {
	Filter *jobsFilterWire `json:"filter,omitempty"`
	Page   *int            `json:"page,omitempty"`
}

type fleetResult struct {
	Runners []RunnerView `json:"runners"`
}

func (s *Server) handleAppConn(conn net.Conn) {
	for {
		env, err := wire.ReadMessage(conn)
		if err != nil {
			return
		}
		// subscribe monopolizes the connection as a push stream.
		if env.Type == wire.TypeSubscribe {
			s.handleSubscribe(conn, env.ID)
			return
		}
		if err := s.serveAppFrame(conn, env); err != nil {
			return
		}
	}
}

func (s *Server) serveAppFrame(conn net.Conn, env wire.Envelope) error {
	switch env.Type {
	case "job", "wait":
		req, err := wire.DecodeBody[jobRequest](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		result, werr := s.d.job(s.ctx, req.JobID, env.Type == "wait")
		if werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, "job_result", result)
	case wire.TypeEnqueue:
		req, err := wire.DecodeBody[wire.Enqueue](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		res, werr := s.d.Enqueue(req)
		if werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeEnqueueResult, res)
	case wire.TypeAck:
		req, err := wire.DecodeBody[wire.Ack](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Ack(req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	case wire.TypeApprove:
		req, err := wire.DecodeBody[wire.Approval](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Approve(req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	case wire.TypeReject:
		req, err := wire.DecodeBody[wire.Approval](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Reject(req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	case wire.TypeCancel:
		req, err := wire.DecodeBody[wire.Cancel](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		if werr := s.d.Cancel(req); werr != nil {
			return replyErr(conn, env.ID, werr)
		}
		return reply(conn, env.ID, wire.TypeOK, wire.OK{})
	case wire.TypeJobs:
		req, err := wire.DecodeBody[jobsRequest](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		f := JobsFilter{}
		if req.Filter != nil {
			f.State, f.Lane, f.JobKeyPrefix = req.Filter.State, req.Filter.Lane, req.Filter.JobKeyPrefix
		}
		if req.Page != nil {
			f.Offset = *req.Page
		}
		res, err := s.d.Jobs(f)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInternal, Message: err.Error()})
		}
		return reply(conn, env.ID, typeJobsResult, res)
	case wire.TypeFleet:
		fleet, err := s.d.Fleet()
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInternal, Message: err.Error()})
		}
		return reply(conn, env.ID, typeFleetResult, fleetResult{Runners: fleet})
	case wire.TypeBudget:
		b, err := s.d.Budget()
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInternal, Message: err.Error()})
		}
		return reply(conn, env.ID, typeBudgetResult, b)
	case wire.TypeSweep:
		res, err := s.d.Sweep()
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInternal, Message: err.Error()})
		}
		return reply(conn, env.ID, typeSweepResult, res)
	case wire.TypeStats:
		req, err := wire.DecodeBody[StatsRequest](env)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: err.Error()})
		}
		res, err := s.d.Stats(req)
		if err != nil {
			return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInternal, Message: err.Error()})
		}
		return reply(conn, env.ID, typeStatsResult, res)
	default:
		return replyErr(conn, env.ID, &wire.Error{Code: wire.CodeInvalid, Message: "unknown app verb " + env.Type})
	}
}

// handleSubscribe streams completions. Correctness comes from the PERSISTING
// inbox in the DB; the in-process wake channel is only a nudge. A newer
// subscribe supersedes this one (takeover). Acks arrive on a separate
// connection, so this handler only writes.
func (s *Server) handleSubscribe(conn net.Conn, subID string) {
	sub := s.d.subs.register()
	defer s.d.subs.deregister(sub)

	// Detect client disconnect by reading (and discarding) from the conn.
	disconnect := make(chan struct{})
	go func() {
		defer close(disconnect)
		buf := make([]byte, 512)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()

	sent := map[string]bool{}
	wake, takeover := sub.waitChans()
	for {
		batch, err := s.d.persistingBatch(sent)
		if err != nil {
			_ = replyErr(conn, subID, &wire.Error{Code: wire.CodeInternal, Message: err.Error()})
			return
		}
		for _, c := range batch {
			if err := reply(conn, subID, wire.TypeCompletion, c); err != nil {
				return
			}
			sent[c.JobID] = true
		}
		select {
		case <-wake:
		case <-takeover:
			_ = reply(conn, subID, wire.TypeTakeover, wire.Takeover{})
			return
		case <-disconnect:
			return
		case <-s.ctx.Done():
			return
		}
	}
}
