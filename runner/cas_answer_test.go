package runner

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// silentCAS takes every connection and never answers on it, like a hung CAS backend.
func silentCAS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			conn.Close()
		}
	})
	return "http://" + ln.Addr().String()
}

// A CAS that takes a request and never answers fails the transfer as unreachable,
// which releases the job back to the queue. Without a bound the runner waited
// forever, and its heartbeats kept renewing the lease of a job that never moved.
func TestACASThatNeverAnswersFailsTheTransferAsUnreachable(t *testing.T) {
	cas := NewCAS(silentCAS(t), answerBoundClient(100*time.Millisecond), nil)
	address := artifact.Address("sha256:" + strings.Repeat("ab", 32))

	done := make(chan error, 1)
	go func() {
		_, err := cas.GetToFile(context.Background(), address, filepath.Join(t.TempDir(), "blob"))
		done <- err
	}()
	select {
	case err := <-done:
		var ce *casError
		if !errors.As(err, &ce) || ce.kind != casUnreachable {
			t.Fatalf("got %v, want an unreachable CAS", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the transfer still waits on a CAS that never answers")
	}
}

func TestTheRunnersCASClientBoundsItsWaitForAnAnswer(t *testing.T) {
	r := New(Config{RunnerID: "R1", CASBaseURL: "http://cas", Lanes: []string{"embed"}}, nil, nil, slog.Default())
	transport, ok := r.cas.hc.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout != casAnswerTimeout {
		t.Fatalf("the runner's CAS client does not bound its wait for an answer: %#v", r.cas.hc.Transport)
	}
}
