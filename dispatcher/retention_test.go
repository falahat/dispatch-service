package dispatcher

import (
	"path/filepath"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

const dayMS = int64(86_400_000)

func retentionDispatcher(t *testing.T, days int) (*Dispatcher, *ManualClock) {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	clk := NewManualClock(1_000_000)
	cfg := testConfig()
	cfg.JobRetentionDays = days
	d, err := New(store, cfg, clk)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	return d, clk
}

func exists(t *testing.T, d *Dispatcher, id string) bool {
	t.Helper()
	_, err := d.GetJob(id)
	return err == nil
}

// TestRetentionPrunesOldTerminalOnly verifies the opt-in retention window: terminal
// jobs older than it are deleted, but recent terminal jobs and any non-terminal
// (live) job survive. Domain data never lives in this DB, so nothing else is at risk.
func TestRetentionPrunesOldTerminalOnly(t *testing.T) {
	d, clk := retentionDispatcher(t, 7)

	// An old terminal job: enqueue + cancel now (-> CANCELLED, updated_ts = now).
	old := enqueueOne(t, d, "old", "embed", invAddr("a"), nil)
	if werr := d.Cancel(wire.Cancel{JobID: old, Reason: "test"}); werr != nil {
		t.Fatalf("cancel old: %v", werr)
	}
	// A live (QUEUED) job that must never be pruned.
	live := enqueueOne(t, d, "live", "embed", invAddr("b"), nil)

	// Jump 8 days: the old terminal job is now past the 7-day window.
	clk.Set(clk.NowMS() + 8*dayMS)

	// A fresh terminal job (cancelled just now) must survive the same sweep.
	recent := enqueueOne(t, d, "recent", "embed", invAddr("c"), nil)
	if werr := d.Cancel(wire.Cancel{JobID: recent, Reason: "test"}); werr != nil {
		t.Fatalf("cancel recent: %v", werr)
	}

	res, err := d.Sweep()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Pruned != 1 {
		t.Fatalf("pruned = %d, want 1 (only the old terminal job)", res.Pruned)
	}
	if exists(t, d, old) {
		t.Fatal("old terminal job should have been pruned")
	}
	if !exists(t, d, live) {
		t.Fatal("live QUEUED job must never be pruned")
	}
	if !exists(t, d, recent) {
		t.Fatal("recent terminal job (within window) must not be pruned")
	}
}

// TestRetentionZeroKeepsForever verifies the default: JobRetentionDays 0 = no TTL,
// so a terminal job is never pruned no matter how old.
func TestRetentionZeroKeepsForever(t *testing.T) {
	d, clk := retentionDispatcher(t, 0)
	id := enqueueOne(t, d, "k", "embed", invAddr("a"), nil)
	if werr := d.Cancel(wire.Cancel{JobID: id, Reason: "test"}); werr != nil {
		t.Fatalf("cancel: %v", werr)
	}
	clk.Set(clk.NowMS() + 3650*dayMS) // 10 years on

	res, err := d.Sweep()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Pruned != 0 {
		t.Fatalf("pruned = %d, want 0 (no TTL)", res.Pruned)
	}
	if !exists(t, d, id) {
		t.Fatal("with no TTL, terminal jobs must be kept forever")
	}
}
