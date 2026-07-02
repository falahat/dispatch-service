package runner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/falahat/dispatch-service/runner"
)

// --- stub CAS (map-backed, verify-on-write) — the T0.3 CAS test double ---

type stubCAS struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func newStubCAS() *stubCAS { return &stubCAS{blobs: map[string][]byte{}} }

func (s *stubCAS) put(b []byte) artifact.Address {
	a := artifact.ComputeAddress(b)
	s.mu.Lock()
	s.blobs[a.Hex()] = b
	s.mu.Unlock()
	return a
}

func (s *stubCAS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/blobs/sha256/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(404)
			return
		}
		hexName := strings.TrimPrefix(r.URL.Path, prefix)
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			b, ok := s.blobs[hexName]
			s.mu.Unlock()
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(b)
		case http.MethodHead:
			s.mu.Lock()
			b, ok := s.blobs[hexName]
			s.mu.Unlock()
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", itoa(len(b)))
			w.WriteHeader(200)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != hexName {
				w.WriteHeader(400) // hash_mismatch
				return
			}
			s.mu.Lock()
			_, existed := s.blobs[hexName]
			s.blobs[hexName] = body
			s.mu.Unlock()
			if existed {
				w.WriteHeader(200)
			} else {
				w.WriteHeader(201)
			}
		default:
			w.WriteHeader(405)
		}
	})
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// --- stub compute (echo): copies each input to outputs/<name> ---

func echoComputeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "op": "echo", "op_version": 1})
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		var req runner.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error_class": "bad_input", "message": err.Error()})
			return
		}
		outputs := map[string]string{}
		var total int64
		outDir := filepath.Join(req.Workdir, req.OutputsDir)
		os.MkdirAll(outDir, 0o755)
		for name, rel := range req.Inputs {
			src := filepath.Join(req.Workdir, filepath.FromSlash(rel))
			data, err := os.ReadFile(src)
			if err != nil {
				w.WriteHeader(500)
				json.NewEncoder(w).Encode(map[string]string{"error_class": "bad_input", "message": "missing input " + name})
				return
			}
			dst := filepath.Join(outDir, name)
			os.WriteFile(dst, data, 0o644)
			outputs[name] = filepath.ToSlash(filepath.Join(req.OutputsDir, name))
			total += int64(len(data))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"outputs": outputs,
			"metrics": map[string]int64{"bytes": total, "outputs": int64(len(outputs))},
		})
	})
	return mux
}

// --- framed app client helper ---

type appClient struct {
	t    *testing.T
	conn net.Conn
}

func dialApp(t *testing.T, addr string) *appClient {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial app: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return &appClient{t: t, conn: c}
}

func (a *appClient) call(id, typ string, body any) wire.Envelope {
	if err := wire.WriteMessage(a.conn, id, typ, body); err != nil {
		a.t.Fatalf("write %s: %v", typ, err)
	}
	a.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := wire.ReadMessage(a.conn)
	if err != nil {
		a.t.Fatalf("read %s reply: %v", typ, err)
	}
	return env
}

func startDispatcher(t *testing.T) *dispatcher.Server {
	dir := t.TempDir()
	store, err := dispatcher.OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := dispatcher.DefaultConfig()
	cfg.RunnerListen = "127.0.0.1:0"
	cfg.AppListen = "127.0.0.1:0"
	cfg.AppSocket = ""
	cfg.MaxWaitS = 2
	cfg.SweepIntervalS = 1
	cfg.Lanes = map[string]dispatcher.LaneConfig{"embed": {Concurrency: 4, PersistingWatermark: 64}}
	d, err := dispatcher.New(store, cfg, dispatcher.RealClock)
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	srv := dispatcher.NewServer(d, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// TestRunnerEndToEnd drives a real job through the runner against a real
// dispatcher, a stub CAS, and an in-process echo compute.
func TestRunnerEndToEnd(t *testing.T) {
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	computeSrv := httptest.NewServer(echoComputeHandler())
	defer computeSrv.Close()

	// Seed the CAS: an input blob and the invocation referencing it.
	inputData := []byte("the quick brown fox")
	dataAddr := cas.put(inputData)
	inv := artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "echo", OpVersion: 1,
		Params: json.RawMessage(`{"n":1}`),
		Inputs: map[string]artifact.Input{"data": {Address: dataAddr, Kind: artifact.KindBlob}},
	}
	invBytes, _ := json.Marshal(inv)
	invAddr := cas.put(invBytes)

	// Enqueue.
	app := dialApp(t, srv.AppAddr())
	env := app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "e2e-k", Lane: "embed", InvocationAddress: invAddr},
	}})
	er, _ := wire.DecodeBody[wire.EnqueueResult](env)
	jobID := er.Results[0].JobID

	// Start the runner.
	rn := runner.New(runner.Config{
		RunnerID: "Re2e", Node: "n1", Version: "runner/test",
		DispatcherAddr: srv.RunnerAddr(),
		CASBaseURL:     casSrv.URL,
		ComputeAddr:    strings.TrimPrefix(computeSrv.URL, "http://"),
		WorkRoot:       t.TempDir(),
		Lanes:          []string{"embed"},
		Capacity:       1,
		LeaseWaitS:     2,
	}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rn.Run(ctx)

	// Wait for the job to reach PERSISTING.
	deadline := time.Now().Add(20 * time.Second)
	var jobState string
	var outputAddr artifact.Address
	for time.Now().Before(deadline) {
		je := app.call("j"+itoa(int(time.Now().UnixNano()%100000)), wire.TypeJobs, map[string]any{"filter": map[string]string{"state": "PERSISTING"}})
		var jr struct {
			Jobs []struct {
				JobID string `json:"job_id"`
				State string `json:"state"`
			} `json:"jobs"`
		}
		_ = json.Unmarshal(je.Body, &jr)
		if len(jr.Jobs) == 1 && jr.Jobs[0].JobID == jobID {
			jobState = jr.Jobs[0].State
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if jobState != "PERSISTING" {
		t.Fatalf("job did not reach PERSISTING (got %q)", jobState)
	}

	// Subscribe to fetch the completion and verify the output.
	sub := dialApp(t, srv.AppAddr())
	if err := wire.WriteMessage(sub.conn, "s1", wire.TypeSubscribe, wire.Subscribe{}); err != nil {
		t.Fatal(err)
	}
	sub.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	cenv, err := wire.ReadMessage(sub.conn)
	if err != nil {
		t.Fatalf("read completion: %v", err)
	}
	comp, _ := wire.DecodeBody[wire.Completion](cenv)
	if comp.JobID != jobID {
		t.Fatalf("completion for %s want %s", comp.JobID, jobID)
	}
	if comp.ActionResult.InvocationAddress != invAddr {
		t.Fatalf("invocation_address echoed wrong: %s", comp.ActionResult.InvocationAddress)
	}
	out, ok := comp.ActionResult.Outputs["data"]
	if !ok {
		t.Fatalf("missing output 'data': %+v", comp.ActionResult.Outputs)
	}
	outputAddr = out.Address
	// The echo output must equal the input bytes, so the addresses match.
	if outputAddr != dataAddr {
		t.Fatalf("echo output addr %s != input addr %s", outputAddr, dataAddr)
	}
	// And it must actually be in the CAS (the runner uploaded it).
	cas.mu.Lock()
	_, present := cas.blobs[outputAddr.Hex()]
	cas.mu.Unlock()
	if !present {
		t.Fatalf("output blob not uploaded to CAS")
	}

	// Ack -> SUCCEEDED.
	app.call("a1", wire.TypeAck, wire.Ack{JobID: jobID, Disposition: wire.DispositionPersisted})
	je := app.call("jf", wire.TypeJobs, map[string]any{"filter": map[string]string{"state": "SUCCEEDED"}})
	if !strings.Contains(string(je.Body), jobID) {
		t.Fatalf("job not SUCCEEDED after ack: %s", string(je.Body))
	}
}
