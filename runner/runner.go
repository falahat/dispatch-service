package runner

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Config configures a runner instance. In the container-pair model the runner
// and its compute container share the WorkRoot volume and the compute serves on
// ComputeAddr (INVOKE_ADDR).
type Config struct {
	RunnerID       string   // public-key fingerprint (identity)
	Node           string   // human node name
	Version        string   // runner version string
	DispatcherAddr string   // runner surface (PEP in prod, dispatcher directly in tests)
	CASBaseURL     string   // PEP CAS surface base URL
	ComputeAddr    string   // paired compute container INVOKE_ADDR
	WorkRoot       string   // shared workdir volume root
	Lanes          []string // lanes this runner serves
	Capacity       int      // concurrent slots (this build serves them sequentially per conn)
	LeaseWaitS     int      // long-poll wait
	GPU            string   // optional GPU descriptor for the fleet view
}

// Runner is the worker client aggregate.
type Runner struct {
	cfg     Config
	cas     *CAS
	invoke  *InvokeClient
	log     *slog.Logger
	wrapper FrameWrapper // nil in direct mode

	mu         sync.Mutex
	current    *liveJob
	draining   bool
	leaseAfter int64 // ms; do not lease before this (throttle)
}

type liveJob struct {
	leaseID   string
	jobID     string
	cancel    context.CancelFunc
	abandoned bool
}

// markAbandoned cancels the in-flight job if it matches jobID and records that
// it was abandoned (so processJob stays silent instead of reporting a failure).
func (r *Runner) markAbandoned(jobID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil && r.current.jobID == jobID {
		r.current.abandoned = true
		r.current.cancel()
	}
}

func (r *Runner) setDraining() {
	r.mu.Lock()
	r.draining = true
	r.mu.Unlock()
}

func (r *Runner) setLeaseAfter(ts int64) {
	r.mu.Lock()
	if ts > r.leaseAfter {
		r.leaseAfter = ts
	}
	r.mu.Unlock()
}

// currentStatus builds the heartbeat status and the current lease id (empty if
// idle).
func (r *Runner) currentStatus() (wire.HeartbeatStatus, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := wire.HeartbeatStatus{Node: r.cfg.Node, Lanes: r.cfg.Lanes, Capacity: r.cfg.Capacity, GPU: r.cfg.GPU}
	lease := ""
	if r.current != nil {
		st.CurrentJobID = r.current.jobID
		lease = r.current.leaseID
	}
	return st, lease
}

// New builds a runner. wrapper may be nil (direct/trusted mode); signer may be
// nil (CAS without auth).
func New(cfg Config, signer Signer, wrapper FrameWrapper, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	if cfg.LeaseWaitS <= 0 {
		cfg.LeaseWaitS = 30
	}
	if cfg.Capacity <= 0 {
		cfg.Capacity = 1
	}
	return &Runner{
		cfg:     cfg,
		cas:     NewCAS(cfg.CASBaseURL, &http.Client{}, signer),
		invoke:  NewInvokeClient(cfg.ComputeAddr),
		log:     log,
		wrapper: wrapper,
	}
}

func (r *Runner) ident() wire.RunnerIdent {
	return wire.RunnerIdent{
		ID: r.cfg.RunnerID, Version: r.cfg.Version, Node: r.cfg.Node,
		Lanes: r.cfg.Lanes, Capacity: r.cfg.Capacity,
	}
}

func (r *Runner) setCurrent(j *liveJob) {
	r.mu.Lock()
	r.current = j
	r.mu.Unlock()
}

func (r *Runner) clearCurrent() {
	r.mu.Lock()
	r.current = nil
	r.mu.Unlock()
}

func (r *Runner) isDraining() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.draining
}
