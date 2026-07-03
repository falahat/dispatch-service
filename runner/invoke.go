package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// InvokeClient speaks the invoke protocol (INVOKE.md) to a compute container
// over HTTP/1.1, on either a host:port or a unix socket (INVOKE_ADDR).
type InvokeClient struct {
	baseURL string
	hc      *http.Client
}

// NewInvokeClient builds a client for INVOKE_ADDR. A value containing a slash or
// a "unix:" prefix is a unix socket path; otherwise it is host:port.
//
// Keep-alive is DISABLED: every invoke (and healthz) uses a fresh connection. The
// compute server is single-flight, so if an invoke is ever cancelled (an abandon)
// or rejected (409) mid-body, its connection can be left byte-misaligned; reusing
// a pooled connection in that state makes the NEXT invoke read a stale body as its
// request line (501/400), which cascades into failing the whole queue. A fresh
// connection per request makes any such fault self-contained.
func NewInvokeClient(addr string) *InvokeClient {
	if strings.HasPrefix(addr, "unix:") || strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, `\`) {
		sock := strings.TrimPrefix(addr, "unix:")
		tr := &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}
		return &InvokeClient{baseURL: "http://unix", hc: &http.Client{Transport: tr}}
	}
	return &InvokeClient{baseURL: "http://" + addr, hc: &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}}
}

// Health is the /healthz response.
type Health struct {
	Ready     bool   `json:"ready"`
	Op        string `json:"op"`
	OpVersion int    `json:"op_version"`
}

// Healthz probes readiness.
func (c *InvokeClient) Healthz(ctx context.Context) (Health, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return Health{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Health{}, fmt.Errorf("healthz status %d", resp.StatusCode)
	}
	var h Health
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return Health{}, err
	}
	return h, nil
}

// InvokeRequest is the POST /invoke body.
type InvokeRequest struct {
	JobID      string            `json:"job_id"`
	Invocation json.RawMessage   `json:"invocation"`
	Workdir    string            `json:"workdir"`
	Inputs     map[string]string `json:"inputs"`
	OutputsDir string            `json:"outputs_dir"`
	DeadlineTS int64             `json:"deadline_ts"`
}

// InvokeResult is a successful /invoke response.
type InvokeResult struct {
	Outputs map[string]string `json:"outputs"`
	Metrics map[string]int64  `json:"metrics"`
}

// InvokeFailure classifies a compute failure (maps to fail{error_class}).
type InvokeFailure struct {
	ErrClass string `json:"error_class"`
	Message  string `json:"message"`
}

func (f *InvokeFailure) Error() string { return f.ErrClass + ": " + f.Message }

// ErrBusy indicates the compute rejected a concurrent invoke (409).
type ErrBusy struct{}

func (ErrBusy) Error() string { return "compute busy (409)" }

// Invoke runs one computation. A non-nil *InvokeFailure means the compute
// reported a classified failure; a plain error means a transport/protocol fault
// (mapped to fatal by the caller).
func (c *InvokeClient) Invoke(ctx context.Context, req InvokeRequest) (*InvokeResult, *InvokeFailure, error) {
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/invoke", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(hreq)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			Outputs map[string]string          `json:"outputs"`
			Metrics map[string]json.RawMessage `json:"metrics"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, nil, fmt.Errorf("invoke: bad 200 body: %w", err)
		}
		res := &InvokeResult{Outputs: out.Outputs, Metrics: map[string]int64{}}
		for k, v := range out.Metrics {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil {
				res.Metrics[k] = n
			}
			// Non-integer metrics are dropped (integer-only rule); not fatal.
		}
		return res, nil, nil
	case http.StatusConflict:
		return nil, nil, ErrBusy{}
	case http.StatusInternalServerError:
		var f InvokeFailure
		if err := json.Unmarshal(raw, &f); err != nil || f.ErrClass == "" {
			return nil, &InvokeFailure{ErrClass: "unknown", Message: string(raw)}, nil
		}
		return nil, &f, nil
	default:
		return nil, nil, fmt.Errorf("invoke: unexpected status %d: %s", resp.StatusCode, string(raw))
	}
}

// WaitReady polls /healthz until ready or the deadline.
func (c *InvokeClient) WaitReady(ctx context.Context, timeout time.Duration) (Health, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		h, err := c.Healthz(ctx)
		if err == nil && h.Ready {
			return h, nil
		}
		last = err
		select {
		case <-ctx.Done():
			return Health{}, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if last == nil {
		last = fmt.Errorf("not ready before timeout")
	}
	return Health{}, last
}
