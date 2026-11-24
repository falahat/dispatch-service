//go:build unix

package e2e

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAPEPOutOfFilesPausesBetweenAccepts fills the PEP's file descriptors with idle
// connections, so every accept fails at once until one of them closes. A PEP that tried
// again at once would spin and log every failure, tens of thousands a second. It must
// pause between tries, and accept again once the connections close.
func TestAPEPOutOfFilesPausesBetweenAccepts(t *testing.T) {
	srv := startDispatcherWaiting(t, 2)
	casSrv := httptest.NewServer(newStubCAS().handler())
	defer casSrv.Close()
	p := startPlanePEP(t, srv, casSrv.URL, 64)

	idle := make([]net.Conn, 0, 100)
	for range cap(idle) {
		c, err := net.Dial("tcp", p.casListen)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		idle = append(idle, c)
	}
	time.Sleep(2 * time.Second)
	failed := strings.Count(p.log.String(), "cas: accept:")
	for _, c := range idle {
		c.Close()
	}
	if failed == 0 || failed > 5 {
		t.Fatalf("%d failed accepts logged in 2 s out of file descriptors, want 1 to 5", failed)
	}

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + p.casListen + "/blobs/sha256/" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("once its connections closed, the PEP did not answer: %v", err)
	}
	resp.Body.Close()
}
