package dispatcher

import (
	"crypto/rand"
	"sync"

	"github.com/oklog/ulid/v2"
)

// IDGen mints time-sortable ULIDs with a type prefix. job_id = "j_"+ULID and
// lease_id = "l_"+ULID, matching the wire patterns. ULIDs are monotonic within
// a millisecond so ids minted in a burst still sort by creation order.
type IDGen struct {
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewIDGen returns an ID generator seeded from crypto/rand.
func NewIDGen() *IDGen {
	return &IDGen{entropy: ulid.Monotonic(rand.Reader, 0)}
}

// JobID mints a job_id stamped at ms.
func (g *IDGen) JobID(ms int64) string { return "j_" + g.newULID(ms) }

// LeaseID mints a lease_id stamped at ms.
func (g *IDGen) LeaseID(ms int64) string { return "l_" + g.newULID(ms) }

func (g *IDGen) newULID(ms int64) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return ulid.MustNew(uint64(ms), g.entropy).String()
}
