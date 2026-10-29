package contracts_test

import (
	"sort"
	"testing"

	"github.com/falahat/dispatch-service/contracts"
)

func TestStatesAndTerminals(t *testing.T) {
	sm := contracts.Machine()
	want := map[string]bool{
		"AWAITING_APPROVAL": false, "QUEUED": false, "RUNNING": false, "PERSISTING": false,
		"SUCCEEDED": true, "FAILED": true, "REJECTED": true, "CANCELLED": true,
	}
	if len(sm.States) != len(want) {
		t.Fatalf("state count = %d, want %d", len(sm.States), len(want))
	}
	for name, terminal := range want {
		if !sm.IsState(name) {
			t.Errorf("missing state %s", name)
		}
		if sm.IsTerminal(name) != terminal {
			t.Errorf("state %s terminal = %v, want %v", name, sm.IsTerminal(name), terminal)
		}
	}
}

func TestLegalTransitions(t *testing.T) {
	sm := contracts.Machine()
	cases := []struct {
		from, event string
		want        []string
	}{
		{"", "enqueue", []string{"AWAITING_APPROVAL", "QUEUED"}},
		{"AWAITING_APPROVAL", "approve", []string{"QUEUED"}},
		{"AWAITING_APPROVAL", "reject", []string{"REJECTED"}},
		{"QUEUED", "claim", []string{"RUNNING"}},
		{"RUNNING", "complete", []string{"PERSISTING"}},
		{"RUNNING", "fail", []string{"FAILED", "QUEUED"}},
		{"RUNNING", "release", []string{"FAILED", "QUEUED"}},
		{"RUNNING", "lease_expired", []string{"FAILED", "QUEUED"}},
		{"PERSISTING", "ack", []string{"CANCELLED", "FAILED", "SUCCEEDED"}},
		{"QUEUED", "cancel", []string{"CANCELLED"}},
		{"RUNNING", "cancel", []string{"CANCELLED", "RUNNING"}},
		{"PERSISTING", "cancel", []string{"CANCELLED", "PERSISTING"}},
	}
	for _, c := range cases {
		got := sm.LegalTargets(c.from, c.event)
		sort.Strings(got)
		sort.Strings(c.want)
		if len(got) != len(c.want) {
			t.Errorf("%s+%s -> %v, want %v", c.from, c.event, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s+%s -> %v, want %v", c.from, c.event, got, c.want)
				break
			}
		}
	}
}

func TestIllegalTransitionsHaveNoTargets(t *testing.T) {
	sm := contracts.Machine()
	illegal := []struct{ from, event string }{
		{"QUEUED", "complete"},  // can't complete what never ran
		{"RUNNING", "ack"},      // ack is app-side from PERSISTING only
		{"SUCCEEDED", "claim"},  // terminal
		{"FAILED", "complete"},  // terminal
		{"PERSISTING", "claim"}, // in the inbox, not runnable
		{"QUEUED", "heartbeat"}, // not an event on QUEUED
		{"AWAITING_APPROVAL", "claim"},
	}
	for _, c := range illegal {
		if got := sm.LegalTargets(c.from, c.event); len(got) != 0 {
			t.Errorf("expected %s+%s illegal, got targets %v", c.from, c.event, got)
		}
	}
}
