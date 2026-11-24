//go:build unix

package e2e

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/falahat/dispatch-service/dispatcher"
	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	runnerpkg "github.com/falahat/dispatch-service/runner"
)

// planePEP is a running PEP fronting a dispatcher's runner surface and a CAS.
type planePEP struct {
	cmd          *exec.Cmd
	exited       chan error
	runnerListen string
	casListen    string
	signerBin    string
	secrets      string
}

func startPlanePEP(t *testing.T, srv *dispatcher.Server, casURL string) *planePEP {
	t.Helper()
	pep := binPath(t, "pep")
	p := &planePEP{
		exited:       make(chan error, 1),
		runnerListen: freePort(t),
		casListen:    freePort(t),
		signerBin:    binPath(t, "signer"),
	}
	tmp := t.TempDir()
	p.secrets = filepath.Join(tmp, "secrets.json")
	rootPub := runSigner(t, p.signerBin, p.secrets, "pubkey")
	p.cmd = exec.Command(pep)
	p.cmd.Env = append(os.Environ(),
		"PEP_ROOT_PUBKEY="+rootPub,
		"PEP_DISPATCHER_ADDR="+srv.RunnerAddr(),
		"PEP_CAS_BACKEND="+casURL,
		"PEP_RUNNER_LISTEN="+p.runnerListen,
		"PEP_CAS_LISTEN="+p.casListen,
		"PEP_NONCE_DB="+filepath.Join(tmp, "nonces.redb"),
		"PEP_REVOCATION_DB="+filepath.Join(tmp, "revocations.json"),
		"RUST_LOG=warn",
	)
	p.cmd.Stdout, p.cmd.Stderr = os.Stderr, os.Stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start pep: %v", err)
	}
	go func() { p.exited <- p.cmd.Wait() }()
	t.Cleanup(func() { _ = p.cmd.Process.Kill() })
	waitDial(t, p.runnerListen, 10*time.Second)
	waitDial(t, p.casListen, 10*time.Second)
	return p
}

// credential enrolls a fresh key with rights on lane embed.
func (p *planePEP) credential(t *testing.T, rights string) *runnerpkg.Credential {
	t.Helper()
	seed, pubHex, err := runnerpkg.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	biscuit := runSigner(t, p.signerBin, p.secrets, "enroll", "--pubkey", pubHex, "--rights", rights, "--lanes", "embed")
	return &runnerpkg.Credential{Biscuit: biscuit, PubkeyHex: pubHex, SeedB64: seed}
}

// waitingLease connects a runner through the PEP, says hello, and leaves a lease waiting
// up to 30 s on an empty queue.
func (p *planePEP) waitingLease(t *testing.T) net.Conn {
	t.Helper()
	cred := p.credential(t, "hello,lease")
	ps, err := runnerpkg.NewPoPSigner(cred)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", p.runnerListen)
	if err != nil {
		t.Fatalf("dial runner surface: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	send := func(id, typ string, body any) {
		inner, err := wire.MarshalEnvelope(id, typ, body)
		if err != nil {
			t.Fatal(err)
		}
		outer, err := ps.Wrap(typ, inner)
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.WriteFrame(conn, outer); err != nil {
			t.Fatalf("send %s: %v", typ, err)
		}
	}
	send("h1", wire.TypeHello, wire.Hello{Contract: wire.ContractVersion, Runner: wire.RunnerIdent{
		ID: cred.PubkeyHex, Version: "runner/test", Node: "n1", Lanes: []string{"embed"}, Capacity: 1,
	}})
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if env, err := wire.ReadMessage(conn); err != nil || env.Type != wire.TypeHelloOK {
		t.Fatalf("hello: %v %s %s", err, env.Type, env.Body)
	}
	send("l1", wire.TypeLease, wire.Lease{Lanes: []string{"embed"}, WaitS: 30})
	time.Sleep(200 * time.Millisecond) // the lease reaches the dispatcher and waits
	return conn
}

// jobStateAfterEnqueue enqueues a job and reports its state once a waiting lease, had
// one been left, would have claimed it.
func jobStateAfterEnqueue(t *testing.T, srv *dispatcher.Server, key string) string {
	t.Helper()
	appCall(t, srv.AppAddr(), "e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{
		{JobKey: key, Lane: "embed", InvocationAddress: artifact.ComputeAddress([]byte(key))},
	}})
	time.Sleep(2 * time.Second)
	env := appCall(t, srv.AppAddr(), "j1", wire.TypeJobs, map[string]any{"filter": map[string]string{"job_key_prefix": key}})
	res, err := wire.DecodeBody[wire.JobsResult](env)
	if err != nil || len(res.Jobs) != 1 {
		t.Fatalf("jobs %s: %v %s", key, err, env.Body)
	}
	return res.Jobs[0].State
}

// TestTheStoppedPEPFinishesItsWork stops the PEP the way a container runtime does, with
// SIGTERM, while it relays a CAS read and a runner's lease waits. It must refuse new
// connections at once, drop the lease (it holds no work yet, and the dispatcher must grant
// nothing into it), finish the read, and exit 0. Before, the PEP had no SIGTERM handler:
// as PID 1 it ignored the signal until the runtime killed it 10 s later.
func TestTheStoppedPEPFinishesItsWork(t *testing.T) {
	srv := startDispatcherWaiting(t, 30)
	cas := newStubCAS()
	blob := []byte("in flight when the stop came")
	addr := cas.put(blob)
	reading, answer := make(chan struct{}, 1), make(chan struct{})
	casSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reading <- struct{}{}:
		default:
		}
		<-answer
		cas.handler().ServeHTTP(w, r)
	}))
	defer casSrv.Close()
	answered := false
	defer func() {
		if !answered {
			close(answer)
		}
	}()
	p := startPlanePEP(t, srv, casSrv.URL)
	runner := p.waitingLease(t)

	reader, err := runnerpkg.NewPoPSigner(p.credential(t, "cas_get"))
	if err != nil {
		t.Fatal(err)
	}
	path := "/blobs/sha256/" + addr.Hex()
	req, _ := http.NewRequest(http.MethodGet, "http://"+p.casListen+path, nil)
	if err := reader.SignCAS(req, http.MethodGet, path); err != nil {
		t.Fatal(err)
	}
	type read struct {
		status int
		body   []byte
		err    error
	}
	got := make(chan read, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			got <- read{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		got <- read{resp.StatusCode, body, err}
	}()
	select {
	case <-reading:
	case <-time.After(10 * time.Second):
		t.Fatal("the CAS read never reached the backend")
	}

	stopped := time.Now()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		c, err := net.DialTimeout("tcp", p.casListen, 200*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the PEP still accepts connections 2 s after SIGTERM")
		}
	}
	runner.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := wire.ReadMessage(runner); !errors.Is(err, io.EOF) {
		t.Fatalf("the waiting lease: %v, want its connection closed", err)
	}

	close(answer)
	answered = true
	select {
	case r := <-got:
		if r.err != nil || r.status != http.StatusOK || !bytes.Equal(r.body, blob) {
			t.Fatalf("the read in flight: status %d, %d bytes, err %v; want 200 and the blob", r.status, len(r.body), r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read in flight never finished")
	}
	select {
	case err := <-p.exited:
		if err != nil {
			t.Fatalf("pep exited with %v, want 0", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the PEP is still running after its last request finished")
	}
	t.Logf("stopped in %s", time.Since(stopped).Round(time.Millisecond))

	if state := jobStateAfterEnqueue(t, srv, "stop-k"); state != "QUEUED" {
		t.Fatalf("job is %s: it went to the lease the stop dropped", state)
	}
}

// TestARunnerThatLeavesMidLeaseIsGrantedNothing: a runner that closes its connection while
// its lease waits (it was stopped, or crashed) is granted nothing. The PEP closes the
// dispatcher's side of the connection, which ends the wait.
func TestARunnerThatLeavesMidLeaseIsGrantedNothing(t *testing.T) {
	srv := startDispatcherWaiting(t, 30)
	casSrv := httptest.NewServer(newStubCAS().handler())
	defer casSrv.Close()
	p := startPlanePEP(t, srv, casSrv.URL)

	p.waitingLease(t).Close()
	time.Sleep(time.Second) // the close travels through the PEP to the dispatcher

	if state := jobStateAfterEnqueue(t, srv, "gone-k"); state != "QUEUED" {
		t.Fatalf("job is %s: it went to a runner that had left", state)
	}
}
