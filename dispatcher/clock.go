package dispatcher

import (
	"sync"
	"time"
)

// Clock is the source of server-stamped time. Every *_ts value in the plane is
// stamped here; runner-reported timings are hints, never truth (invariant 6).
// It is an interface so tests can drive time deterministically.
type Clock interface {
	// NowMS returns the current time in milliseconds since the Unix epoch.
	NowMS() int64
}

// realClock reads the wall clock.
type realClock struct{}

func (realClock) NowMS() int64 { return time.Now().UnixMilli() }

// RealClock is the production clock.
var RealClock Clock = realClock{}

// ManualClock is a test clock advanced explicitly.
type ManualClock struct {
	mu sync.Mutex
	ms int64
}

// NewManualClock starts a manual clock at the given ms.
func NewManualClock(ms int64) *ManualClock { return &ManualClock{ms: ms} }

func (c *ManualClock) NowMS() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ms
}

// Advance moves the manual clock forward by d milliseconds.
func (c *ManualClock) Advance(d int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ms += d
}

// Set fixes the manual clock to ms.
func (c *ManualClock) Set(ms int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ms = ms
}
