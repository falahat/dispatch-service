// Package e2e holds cross-component, cross-language end-to-end tests: the Go
// dispatcher + runner authenticating through the real Rust PEP to a CAS backend.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	runnerpkg "github.com/falahat/dispatch-service/runner"
)

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func binPath(t *testing.T, name string) string {
	// The auth crate binaries live under auth/target/debug.
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(thisFile)) // .../dispatch-service
	p := filepath.Join(root, "auth", "target", "debug", exeName(name))
	if _, err := os.Stat(p); err != nil {
		t.Skipf("auth binary %s not built (%v); run: cargo build --manifest-path auth/Cargo.toml", name, err)
	}
	return p
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitDial(t *testing.T, addr string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after %s", addr, d)
}

// --- stub CAS backend (map-backed, verify-on-write) ---

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

func (s *stubCAS) has(hexAddr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blobs[hexAddr]
	return ok
}

func (s *stubCAS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/blobs/sha256/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(404)
			return
		}
		h := strings.TrimPrefix(r.URL.Path, prefix)
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			b, ok := s.blobs[h]
			s.mu.Unlock()
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(b)
		case http.MethodHead:
			s.mu.Lock()
			b, ok := s.blobs[h]
			s.mu.Unlock()
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(b)))
			w.WriteHeader(200)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != h {
				w.WriteHeader(400)
				return
			}
			s.mu.Lock()
			_, existed := s.blobs[h]
			s.blobs[h] = body
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

// --- echo compute ---

func echoCompute() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "op": "echo", "op_version": 1})
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		var req runnerpkg.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error_class": "bad_input", "message": err.Error()})
			return
		}
		outDir := filepath.Join(req.Workdir, req.OutputsDir)
		os.MkdirAll(outDir, 0o755)
		outputs := map[string]string{}
		var total int64
		for name, rel := range req.Inputs {
			data, err := os.ReadFile(filepath.Join(req.Workdir, filepath.FromSlash(rel)))
			if err != nil {
				w.WriteHeader(500)
				json.NewEncoder(w).Encode(map[string]string{"error_class": "bad_input", "message": "missing " + name})
				return
			}
			os.WriteFile(filepath.Join(outDir, name), data, 0o644)
			outputs[name] = filepath.ToSlash(filepath.Join(req.OutputsDir, name))
			total += int64(len(data))
		}
		json.NewEncoder(w).Encode(map[string]any{"outputs": outputs, "metrics": map[string]int64{"bytes": total}})
	})
	return mux
}

// --- app framed helper ---

func appCall(t *testing.T, addr, id, typ string, body any) wire.Envelope {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial app: %v", err)
	}
	defer c.Close()
	if err := wire.WriteMessage(c, id, typ, body); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := wire.ReadMessage(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return env
}

// signer / dispatcher setup.
func runSigner(t *testing.T, signerBin, secrets string, args ...string) string {
	full := append([]string{"-secrets", secrets}, args...)
	out, err := exec.Command(signerBin, full...).Output()
	if err != nil {
		t.Fatalf("signer %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

func startDispatcher(t *testing.T) *dispatcher.Server {
	dir := t.TempDir()
	store, err := dispatcher.OpenStore(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	srv := dispatcher.NewServer(d, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// TestAuthenticatedPlane drives a full job through the Go runner authenticating
// via the real Rust PEP to both the dispatcher and the CAS backend.
func TestAuthenticatedPlane(t *testing.T) {
	pep := binPath(t, "pep")
	signerBin := binPath(t, "signer")

	tmp := t.TempDir()
	secrets := filepath.Join(tmp, "secrets.json")
	rootPub := runSigner(t, signerBin, secrets, "pubkey")

	// Runner keypair + enrollment -> credential file.
	seed, pubHex, err := runnerpkg.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	biscuit := runSigner(t, signerBin, secrets, "enroll", "--pubkey", pubHex,
		"--rights", "hello,lease,heartbeat,complete,fail,release,cas_get,cas_put", "--lanes", "embed")
	credFile := filepath.Join(tmp, "cred.json")
	writeJSON(t, credFile, map[string]string{"biscuit": biscuit, "pubkey_hex": pubHex, "seed_b64": seed})

	// Backends.
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	computeSrv := httptest.NewServer(echoCompute())
	defer computeSrv.Close()

	// Seed the CAS with the invocation + its input.
	input := []byte("authenticated bytes")
	dataAddr := cas.put(input)
	inv := artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "echo", OpVersion: 1, Params: json.RawMessage(`{"n":1}`),
		Inputs: map[string]artifact.Input{"data": {Address: dataAddr, Kind: artifact.KindBlob}},
	}
	invBytes, _ := json.Marshal(inv)
	invAddr := cas.put(invBytes)

	// Start the PEP fronting the dispatcher runner surface + the CAS.
	runnerListen := freePort(t)
	casListen := freePort(t)
	cmd := exec.Command(pep)
	cmd.Env = append(os.Environ(),
		"PEP_ROOT_PUBKEY="+rootPub,
		"PEP_DISPATCHER_ADDR="+srv.RunnerAddr(),
		"PEP_CAS_BACKEND="+casSrv.URL,
		"PEP_RUNNER_LISTEN="+runnerListen,
		"PEP_CAS_LISTEN="+casListen,
		"PEP_NONCE_DB="+filepath.Join(tmp, "nonces.redb"),
		"RUST_LOG=warn",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waitDial(t, runnerListen, 10*time.Second)
	waitDial(t, casListen, 10*time.Second)

	// Enqueue (app surface, direct).
	env := appCall(t, srv.AppAddr(), "e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: "auth-k", Lane: "embed", InvocationAddress: invAddr},
	}})
	er, _ := wire.DecodeBody[wire.EnqueueResult](env)
	jobID := er.Results[0].JobID

	// Runner in PEP mode.
	cred, err := runnerpkg.LoadCredential(credFile)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := runnerpkg.NewPoPSigner(cred)
	if err != nil {
		t.Fatal(err)
	}
	rn := runnerpkg.New(runnerpkg.Config{
		RunnerID: pubHex, Node: "n1", Version: "runner/test",
		DispatcherAddr: runnerListen,
		CASBaseURL:     "http://" + casListen,
		ComputeAddr:    strings.TrimPrefix(computeSrv.URL, "http://"),
		WorkRoot:       t.TempDir(),
		Lanes:          []string{"embed"},
		Capacity:       1, LeaseWaitS: 2,
	}, ps, ps, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rn.Run(ctx)

	// The job should complete through the authenticated path.
	deadline := time.Now().Add(25 * time.Second)
	done := false
	for time.Now().Before(deadline) {
		je := appCall(t, srv.AppAddr(), "j1", wire.TypeJobs, map[string]any{"filter": map[string]string{"state": "PERSISTING"}})
		if strings.Contains(string(je.Body), jobID) {
			done = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !done {
		t.Fatal("job never reached PERSISTING through the authenticated plane")
	}
	// The runner uploaded the output through the PEP -> it is in the CAS.
	if !cas.has(dataAddr.Hex()) {
		t.Fatal("expected output present in CAS")
	}
	// Ack -> SUCCEEDED.
	appCall(t, srv.AppAddr(), "a1", wire.TypeAck, wire.Ack{JobID: jobID, Disposition: wire.DispositionPersisted})
}

// TestPEPDenials asserts the CAS surface fails closed for unauthenticated and
// under-privileged requests.
func TestPEPDenials(t *testing.T) {
	pep := binPath(t, "pep")
	signerBin := binPath(t, "signer")
	tmp := t.TempDir()
	secrets := filepath.Join(tmp, "secrets.json")
	rootPub := runSigner(t, signerBin, secrets, "pubkey")

	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	defer casSrv.Close()
	someAddr := cas.put([]byte("secret"))

	casListen := freePort(t)
	runnerListen := freePort(t)
	cmd := exec.Command(pep)
	cmd.Env = append(os.Environ(),
		"PEP_ROOT_PUBKEY="+rootPub,
		"PEP_DISPATCHER_ADDR=127.0.0.1:1", // unused here
		"PEP_CAS_BACKEND="+casSrv.URL,
		"PEP_RUNNER_LISTEN="+runnerListen,
		"PEP_CAS_LISTEN="+casListen,
		"PEP_NONCE_DB="+filepath.Join(tmp, "nonces.redb"),
		"RUST_LOG=warn",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waitDial(t, casListen, 10*time.Second)

	url := "http://" + casListen + "/blobs/sha256/" + someAddr.Hex()

	// 1. No auth headers -> 401.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated GET: status %d, want 401", resp.StatusCode)
	}

	// 2. A credential WITHOUT cas_get -> 403 (authenticated but unauthorized).
	seed, pubHex, _ := runnerpkg.GenerateKeypair()
	biscuit := runSigner(t, signerBin, secrets, "enroll", "--pubkey", pubHex, "--rights", "cas_put", "--lanes", "embed")
	cred := &runnerpkg.Credential{Biscuit: biscuit, PubkeyHex: pubHex, SeedB64: seed}
	ps, _ := runnerpkg.NewPoPSigner(cred)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if err := ps.SignCAS(req, "GET", "/blobs/sha256/"+someAddr.Hex()); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 403 {
		t.Fatalf("under-privileged GET: status %d, want 403", resp2.StatusCode)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
