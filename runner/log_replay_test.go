package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// commandRunnerWithLog makes a command runner whose current job has written text to
// its invoke.log, against a CAS that takes whatever it is sent.
func commandRunnerWithLog(t *testing.T, text string) (*Runner, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "job"), 0700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "job", "invoke.log")
	if err := os.WriteFile(logPath, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	cas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(cas.Close)
	r := New(Config{RunnerID: "worker", Node: "node", Command: []string{"python3"}, WorkRoot: root, CASBaseURL: cas.URL}, nil, nil, nil)
	r.setCurrent(&liveJob{jobID: "job", leaseID: "lease", cancel: func() {}})
	return r, logPath
}

// exchange runs one beat against a dispatcher that answers it with answer's reply,
// or that drops the connection unanswered when answer is nil, and returns what the
// runner sent.
func exchange(t *testing.T, r *Runner, answer func(wire.Heartbeat) wire.BeatOK) (wire.Heartbeat, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	sent := make(chan wire.Heartbeat, 1)
	go func() {
		defer server.Close()
		defer close(sent)
		envelope, err := wire.ReadMessage(server)
		if err != nil {
			return
		}
		heartbeat, err := wire.DecodeBody[wire.Heartbeat](envelope)
		if err != nil {
			return
		}
		sent <- heartbeat
		if answer != nil {
			_ = wire.WriteMessage(server, envelope.ID, wire.TypeBeatOK, answer(heartbeat))
		}
	}()
	err := r.beat(context.Background(), &dispatcherConn{conn: client})
	heartbeat, ok := <-sent
	if !ok {
		t.Fatal("the runner sent no heartbeat")
	}
	return heartbeat, err
}

func acknowledge(heartbeat wire.Heartbeat) wire.BeatOK {
	if heartbeat.Log == nil {
		return wire.BeatOK{Directives: []wire.Directive{}}
	}
	end := heartbeat.Log.Offset + heartbeat.Log.Size
	return wire.BeatOK{Directives: []wire.Directive{}, LogOffset: &end}
}

// A beat whose reply is lost may still have been stored, and the dispatcher takes
// only that same chunk at that offset again. The runner resends it exactly, though
// the command has written more since, and ships the rest after it.
func TestUnacknowledgedLogChunkIsResentExactly(t *testing.T) {
	r, logPath := commandRunnerWithLog(t, "first")
	lost, err := exchange(t, r, nil)
	if err == nil || lost.Log == nil {
		t.Fatalf("an unanswered beat must fail (err %v) after shipping the log (%+v)", err, lost.Log)
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(" and more"); err != nil {
		t.Fatal(err)
	}
	file.Close()

	again, err := exchange(t, r, acknowledge)
	if err != nil {
		t.Fatal(err)
	}
	if again.Log == nil || *again.Log != *lost.Log {
		t.Fatalf("resent chunk %+v, want the unacknowledged %+v exactly", again.Log, lost.Log)
	}
	next, err := exchange(t, r, acknowledge)
	if err != nil {
		t.Fatal(err)
	}
	if next.Log == nil || next.Log.Offset != 5 || next.Log.Size != int64(len(" and more")) {
		t.Fatalf("next chunk %+v, want the 9 bytes after offset 5", next.Log)
	}
}

// A dispatcher that refuses the log answers every beat with an error. Flushing the
// log before a job's result then fails once, instead of resending it in a tight loop
// until the lease runs out.
func TestFlushLogStopsWhenTheDispatcherRefusesTheChunk(t *testing.T) {
	r, _ := commandRunnerWithLog(t, "output")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		for {
			envelope, err := wire.ReadMessage(server)
			if err != nil {
				return
			}
			refusal := wire.Error{Code: wire.CodeInternal, Message: "heartbeat: divergent log chunk"}
			if wire.WriteMessage(server, envelope.ID, wire.TypeError, refusal) != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- r.flushLog(context.Background(), &dispatcherConn{conn: client}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a refused log must end the flush with an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("flushLog kept resending a chunk the dispatcher refuses")
	}
}
