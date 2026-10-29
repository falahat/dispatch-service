package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// CheckReport is the result of a conformance check.
type CheckReport struct {
	Image        string
	HealthOK     bool
	FixtureOK    bool
	DeadlineOK   bool
	MalformedOK  bool
	SingleFlight string // "verified" | "not-observed"
	Notes        []string
}

// Check validates a compute image against the invoke contract (INVOKE.md): it
// runs the container with a shared workdir, gates on /healthz, runs the image's
// fixture invocation, and checks deadline + malformed-request + single-flight
// behavior. fixtureDir may be "" to extract /fixture from the image.
func Check(ctx context.Context, image, fixtureDir string) (*CheckReport, error) {
	rep := &CheckReport{Image: image}

	tmp, err := os.MkdirTemp("", "runner-check-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	if fixtureDir == "" {
		fixtureDir, err = extractFixture(ctx, image, tmp)
		if err != nil {
			return nil, fmt.Errorf("check: could not obtain fixture (pass --fixture): %w", err)
		}
	}
	invBytes, err := os.ReadFile(filepath.Join(fixtureDir, "invocation.json"))
	if err != nil {
		return nil, fmt.Errorf("check: read fixture invocation: %w", err)
	}
	var inv artifact.Invocation
	if err := json.Unmarshal(invBytes, &inv); err != nil {
		return nil, fmt.Errorf("check: fixture invocation invalid JSON: %w", err)
	}
	if err := inv.Validate(); err != nil {
		return nil, fmt.Errorf("check: fixture invocation invalid: %w", err)
	}

	// Lay out the fixture's inputs into a host workdir shared with the container.
	workdir := filepath.Join(tmp, "work")
	if err := os.MkdirAll(filepath.Join(workdir, "inputs"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(workdir, "outputs"), 0o755); err != nil {
		return nil, err
	}
	if src := filepath.Join(fixtureDir, "inputs"); dirExists(src) {
		if err := copyTree(src, filepath.Join(workdir, "inputs")); err != nil {
			return nil, err
		}
	}

	cid, port, err := dockerRunCompute(ctx, image, workdir)
	if err != nil {
		return nil, err
	}
	defer dockerRM(cid)

	ic := NewInvokeClient(fmt.Sprintf("127.0.0.1:%s", port))

	// Health + op match.
	h, err := ic.WaitReady(ctx)
	if err != nil {
		return rep, fmt.Errorf("check: healthz never ready: %w", err)
	}
	rep.HealthOK = true
	if h.Op != inv.Op {
		rep.Notes = append(rep.Notes, fmt.Sprintf("healthz op %q != fixture op %q", h.Op, inv.Op))
	}

	inputs := map[string]string{}
	for name := range inv.Inputs {
		inputs[name] = filepath.ToSlash(filepath.Join("inputs", name))
	}
	deadline := time.Now().Add(30 * time.Second).UnixMilli()

	// Fixture invoke -> 200 + declared outputs exist under the workdir.
	res, failure, ierr := ic.Invoke(ctx, InvokeRequest{
		JobID: "check", Invocation: invBytes, Workdir: "/work",
		Inputs: inputs, OutputsDir: "outputs", DeadlineTS: deadline,
	})
	if ierr != nil || failure != nil {
		return rep, fmt.Errorf("check: fixture invoke failed: %v %v", ierr, failure)
	}
	for name, rel := range res.Outputs {
		if !fileExists(filepath.Join(workdir, filepath.FromSlash(rel))) {
			return rep, fmt.Errorf("check: declared output %q (%s) not present in workdir", name, rel)
		}
	}
	rep.FixtureOK = true

	// Past deadline -> 500 timeout.
	_, f2, e2 := ic.Invoke(ctx, InvokeRequest{
		JobID: "check-dl", Invocation: invBytes, Workdir: "/work",
		Inputs: inputs, OutputsDir: "outputs", DeadlineTS: time.Now().Add(-time.Second).UnixMilli(),
	})
	if f2 != nil && f2.ErrClass == "timeout" {
		rep.DeadlineOK = true
	} else {
		rep.Notes = append(rep.Notes, fmt.Sprintf("past-deadline did not yield timeout (got %v/%v)", f2, e2))
	}

	// Malformed body -> 500.
	if malformedRejected(ctx, port) {
		rep.MalformedOK = true
	} else {
		rep.Notes = append(rep.Notes, "malformed request not rejected with 500")
	}

	// Opportunistic single-flight probe.
	rep.SingleFlight = probeSingleFlight(ctx, ic, invBytes, inputs, deadline)

	return rep, nil
}

// OK reports whether the mandatory checks passed.
func (r *CheckReport) OK() bool {
	return r.HealthOK && r.FixtureOK && r.DeadlineOK && r.MalformedOK
}

func extractFixture(ctx context.Context, image, tmp string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "create", image).Output()
	if err != nil {
		return "", err
	}
	cid := strings.TrimSpace(string(out))
	defer exec.Command("docker", "rm", "-f", cid).Run()
	dst := filepath.Join(tmp, "fixture")
	if err := exec.CommandContext(ctx, "docker", "cp", cid+":/fixture/.", dst).Run(); err != nil {
		return "", err
	}
	return dst, nil
}

func dockerRunCompute(ctx context.Context, image, workdir string) (cid, port string, err error) {
	mount := filepath.ToSlash(workdir)
	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-e", "INVOKE_ADDR=0.0.0.0:8080",
		"-v", mount+":/work",
		"-p", "127.0.0.1:0:8080",
		image).Output()
	if err != nil {
		return "", "", fmt.Errorf("docker run: %w", err)
	}
	cid = strings.TrimSpace(string(out))
	pout, err := exec.CommandContext(ctx, "docker", "port", cid, "8080/tcp").Output()
	if err != nil {
		dockerRM(cid)
		return "", "", fmt.Errorf("docker port: %w", err)
	}
	// e.g. "127.0.0.1:49153"
	line := strings.TrimSpace(strings.Split(string(pout), "\n")[0])
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		dockerRM(cid)
		return "", "", fmt.Errorf("unexpected docker port output: %q", line)
	}
	return cid, line[idx+1:], nil
}

func dockerRM(cid string) { _ = exec.Command("docker", "rm", "-f", cid).Run() }

func probeSingleFlight(ctx context.Context, ic *InvokeClient, invBytes []byte, inputs map[string]string, deadline int64) string {
	var wg sync.WaitGroup
	results := make([]error, 2)
	got409 := false
	var mu sync.Mutex
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := ic.Invoke(ctx, InvokeRequest{
				JobID: "sf", Invocation: invBytes, Workdir: "/work",
				Inputs: inputs, OutputsDir: "outputs", DeadlineTS: deadline,
			})
			if _, busy := err.(ErrBusy); busy {
				mu.Lock()
				got409 = true
				mu.Unlock()
			}
			results[i] = err
		}(i)
	}
	wg.Wait()
	if got409 {
		return "verified"
	}
	return "not-observed"
}

func malformedRejected(ctx context.Context, port string) bool {
	url := fmt.Sprintf("http://127.0.0.1:%s/invoke", port)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{not json"))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 500
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
