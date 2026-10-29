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
