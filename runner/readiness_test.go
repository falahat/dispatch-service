package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestReadinessWaitsForWarmup(t *testing.T) {
	seen, warm := make(chan struct{}), make(chan struct{})
	var first sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Do(func() { close(seen) })
		select {
		case <-warm:
			_, _ = w.Write([]byte(`{"ready":true,"op":"example","op_version":1}`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		health, err := NewInvokeClient(strings.TrimPrefix(server.URL, "http://")).WaitReady(ctx)
		if err == nil && !health.Ready {
			err = errors.New("admitted unready compute")
		}
		done <- err
	}()
	<-seen
	select {
	case err := <-done:
		t.Fatalf("returned during warmup: %v", err)
	default:
	}
	close(warm)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadinessHonorsCancellation(t *testing.T) {
	seen := make(chan struct{})
	var first sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Do(func() { close(seen) })
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewInvokeClient(strings.TrimPrefix(server.URL, "http://")).WaitReady(ctx)
		done <- err
	}()
	<-seen
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

// A runner stopped while its compute warms up was stopped, not failed: its unit
// must not read failed, or the kit's settle refuses to replace it.
func TestRunStoppedAtTheBootGateIsNotAFailure(t *testing.T) {
	seen := make(chan struct{})
	var first sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Do(func() { close(seen) })
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	rn := New(Config{RunnerID: "Rgate", Lanes: []string{"embed"},
		ComputeAddr: strings.TrimPrefix(server.URL, "http://")}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rn.Run(ctx) }()
	<-seen
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stopped at the boot gate: %v", err)
	}
}

func TestRunFailsWhenItsCommandIsMissing(t *testing.T) {
	rn := New(Config{RunnerID: "Rmissing", Lanes: []string{"embed"},
		Command: []string{"/nonexistent/executor"}}, nil, nil, nil)
	if err := rn.Run(context.Background()); err == nil {
		t.Fatal("a runner without its command passed its boot gate")
	}
}
