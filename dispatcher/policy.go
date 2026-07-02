package dispatcher

import (
	"math/rand"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Policy defaults, per contracts/schemas/wire.schema.json #/$defs/policy.
const (
	defaultMaxAttempts  = 3
	defaultBackoffClass = wire.BackoffStandard
	defaultPriority     = 5
	defaultReleaseCap   = 5
)

// ResolvedPolicy is a job's policy with every default applied — the concrete
// rules the dispatcher enforces. `on_drift` is deliberately absent: staleness
// is reconciler (app) policy, never evaluated here (WIRE.md).
type ResolvedPolicy struct {
	MaxAttempts         int
	BackoffClass        wire.BackoffClass
	ErrorClassOverrides map[wire.ErrorClass]string
	ExpectedWallS       int // 0 = unset
	Priority            int
	ReleaseCap          int
}

// ResolvePolicy fills defaults over an optional wire policy.
func ResolvePolicy(p *wire.Policy) ResolvedPolicy {
	r := ResolvedPolicy{
		MaxAttempts:  defaultMaxAttempts,
		BackoffClass: defaultBackoffClass,
		Priority:     defaultPriority,
		ReleaseCap:   defaultReleaseCap,
	}
	if p == nil {
		return r
	}
	if p.MaxAttempts != nil {
		r.MaxAttempts = *p.MaxAttempts
	}
	if p.BackoffClass != nil {
		r.BackoffClass = *p.BackoffClass
	}
	if p.ErrorClassOverrides != nil {
		r.ErrorClassOverrides = p.ErrorClassOverrides
	}
	if p.ExpectedWallS != nil {
		r.ExpectedWallS = *p.ExpectedWallS
	}
	if p.Priority != nil {
		r.Priority = *p.Priority
	}
	if p.ReleaseCap != nil {
		r.ReleaseCap = *p.ReleaseCap
	}
	return r
}

// defaultRetriable is the built-in error-class disposition. Transient classes
// retry (bounded by max_attempts / the poison cap); deterministic failures are
// terminal — retrying them just burns a GPU. A per-job override flips any class.
var defaultRetriable = map[wire.ErrorClass]bool{
	wire.ClassOOM:       true, // retry smaller (batch_scale hint)
	wire.ClassTimeout:   true,
	wire.ClassRateLimit: true,
	wire.ClassNetwork:   true,
	wire.ClassUnknown:   true,  // give it a bounded chance
	wire.ClassBadInput:  false, // deterministic
	wire.ClassIntegrity: false, // deterministic
	wire.ClassFatal:     false, // deterministic
}

// IsRetriable reports whether a failure class should be retried under this
// policy. A per-job override takes precedence over the default.
func (r ResolvedPolicy) IsRetriable(class wire.ErrorClass) bool {
	if r.ErrorClassOverrides != nil {
		if v, ok := r.ErrorClassOverrides[class]; ok {
			return v == "retriable"
		}
	}
	return defaultRetriable[class]
}

// backoffParams is base/cap in ms per class.
type backoffParams struct{ baseMS, capMS int64 }

var backoffTable = map[wire.BackoffClass]backoffParams{
	wire.BackoffQuick:    {baseMS: 1_000, capMS: 30_000},
	wire.BackoffStandard: {baseMS: 5_000, capMS: 300_000},
	wire.BackoffLong:     {baseMS: 30_000, capMS: 3_600_000},
}

// Backoff returns the delay in ms before the given (1-based) attempt may be
// re-claimed: exponential in the attempt with equal jitter (half fixed, half
// random), capped per class. rng is injected for deterministic tests.
func (r ResolvedPolicy) Backoff(attempt int, rng *rand.Rand) int64 {
	p, ok := backoffTable[r.BackoffClass]
	if !ok {
		p = backoffTable[wire.BackoffStandard]
	}
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 20 { // guard against overflow on absurd attempt counts
		shift = 20
	}
	raw := p.baseMS << shift
	if raw > p.capMS || raw <= 0 {
		raw = p.capMS
	}
	half := raw / 2
	jitter := int64(0)
	if half > 0 && rng != nil {
		jitter = rng.Int63n(half)
	}
	return half + jitter
}
