// Package dispatcher is the durable work service: it owns the queue, leases,
// retries, admission, and fleet. It is data-blind — it stores keys and CAS
// addresses, never domain bytes — and it holds no auth crypto (the Rust PEP
// verifies; the dispatcher trusts the PEP-attached identity and enforces only
// live-state authz, i.e. lease fencing). See docs/DISPATCH_PLANE.md.
package dispatcher

import (
	"math/rand"
	"sync"
	"time"
)

// Dispatcher is the running service aggregate.
type Dispatcher struct {
	store *Store
	cfg   Config
	clock Clock
	ids   *IDGen

	rng   *rand.Rand
	rngMu sync.Mutex

	leaseWake *broadcaster // wakes lease long-polls when work may be available
	subs      *subMgr      // the single active app subscription

	rl *rateLimiter
}

// New builds a Dispatcher over an open store and config.
func New(store *Store, cfg Config, clock Clock) (*Dispatcher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = RealClock
	}
	if err := store.SetBudgetCap(cfg.Budget.CapUSD); err != nil {
		return nil, err
	}
	d := &Dispatcher{
		store:     store,
		cfg:       cfg,
		clock:     clock,
		ids:       NewIDGen(),
		rng:       rand.New(rand.NewSource(clock.NowMS())),
		leaseWake: newBroadcaster(),
		subs:      newSubMgr(),
		rl:        newRateLimiter(cfg.RunnerRatePerMin),
	}
	return d, nil
}

// now returns the server-stamped current time in ms.
func (d *Dispatcher) now() int64 { return d.clock.NowMS() }

// GetJob loads a job by id (read path; used by tests and dispatchctl).
func (d *Dispatcher) GetJob(jobID string) (Job, error) { return d.store.GetJob(jobID) }

// backoffRand returns a synchronized *rand.Rand for jitter.
func (d *Dispatcher) backoffRand() *rand.Rand {
	// The math/rand Rand is not safe for concurrent use; callers hold rngMu.
	return d.rng
}

// jitter computes a backoff under lock.
func (d *Dispatcher) jitter(p ResolvedPolicy, attempt int) int64 {
	d.rngMu.Lock()
	defer d.rngMu.Unlock()
	return p.Backoff(attempt, d.rng)
}

// wakeLeases signals any blocked lease long-polls to re-evaluate.
func (d *Dispatcher) wakeLeases() { d.leaseWake.broadcast() }

// --- broadcaster: wake-all with no missed-signal race ---

type broadcaster struct {
	mu sync.Mutex
	ch chan struct{}
}

func newBroadcaster() *broadcaster { return &broadcaster{ch: make(chan struct{})} }

// wait returns the current wake channel; caller selects on it (plus a timeout).
func (b *broadcaster) wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ch
}

// broadcast wakes everyone currently waiting.
func (b *broadcaster) broadcast() {
	b.mu.Lock()
	defer b.mu.Unlock()
	close(b.ch)
	b.ch = make(chan struct{})
}

// --- rate limiter: per-runner grants per minute ---

type rateLimiter struct {
	mu       sync.Mutex
	perMin   int
	grants   map[string][]int64 // runnerID -> recent grant timestamps (ms)
}

func newRateLimiter(perMin int) *rateLimiter {
	return &rateLimiter{perMin: perMin, grants: map[string][]int64{}}
}

// allow reports whether runnerID may receive another grant at nowMS, and if so
// records it. A perMin <= 0 disables the limit.
func (r *rateLimiter) allow(runnerID string, nowMS int64) bool {
	if r.perMin <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := nowMS - 60_000
	ts := r.grants[runnerID]
	kept := ts[:0]
	for _, t := range ts {
		if t > cutoff {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.perMin {
		r.grants[runnerID] = kept
		return false
	}
	kept = append(kept, nowMS)
	r.grants[runnerID] = kept
	return true
}

// --- subscription manager: exactly one active app subscription ---

type subMgr struct {
	mu     sync.Mutex
	active *subscription
}

type subscription struct {
	wake     chan struct{}  // buffered(1): a completion may be available
	takeover chan struct{}  // closed when a newer subscribe supersedes this one
}

func newSubMgr() *subMgr { return &subMgr{} }

// register makes sub the sole active subscription, superseding any prior one
// (which receives a takeover). Returns sub.
func (m *subMgr) register() *subscription {
	sub := &subscription{wake: make(chan struct{}, 1), takeover: make(chan struct{})}
	m.mu.Lock()
	prev := m.active
	m.active = sub
	m.mu.Unlock()
	if prev != nil {
		close(prev.takeover) // newest-connection-wins
	}
	return sub
}

// deregister clears sub if it is still the active one.
func (m *subMgr) deregister(sub *subscription) {
	m.mu.Lock()
	if m.active == sub {
		m.active = nil
	}
	m.mu.Unlock()
}

// notify wakes the active subscription (best-effort; correctness comes from the
// PERSISTING inbox in the DB, this is only a wakeup).
func (m *subMgr) notify() {
	m.mu.Lock()
	sub := m.active
	m.mu.Unlock()
	if sub == nil {
		return
	}
	select {
	case sub.wake <- struct{}{}:
	default:
	}
}

// clampWait bounds a requested long-poll wait to the server's configured range.
func (d *Dispatcher) clampWait(waitS int) time.Duration {
	if waitS < d.cfg.MinWaitS {
		waitS = d.cfg.MinWaitS
	}
	if waitS > d.cfg.MaxWaitS {
		waitS = d.cfg.MaxWaitS
	}
	return time.Duration(waitS) * time.Second
}
