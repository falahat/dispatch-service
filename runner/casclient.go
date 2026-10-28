// Package runner is the shared worker client: it leases jobs from the
// dispatcher, moves bytes through the CAS, drives a compute container over the
// invoke protocol, and reports terminal verbs. It holds a credential but no
// domain logic — any compute image, any language, behind the invoke contract.
package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// Signer adds auth (Biscuit + PoP) to a CAS HTTP request. In direct/trusted
// mode it is nil; in production the PEP-facing signer attaches per-request
// credentials. Kept an interface so the runner is testable without the PEP.
type Signer interface {
	SignCAS(req *http.Request, method, casPath string) error
}

// CAS is an HTTP client for the byte plane, as exposed by the PEP (CAS.md).
// Trust lives in the address, never the store: every read is verified.
type CAS struct {
	baseURL string
	hc      *http.Client
	signer  Signer
}

// NewCAS builds a CAS client against baseURL (e.g. http://pep:8080). signer may
// be nil for direct/trusted deployments.
func NewCAS(baseURL string, hc *http.Client, signer Signer) *CAS {
	if strings.HasPrefix(baseURL, "file://") {
		location, err := url.Parse(baseURL)
		if err == nil && location.Host == "" {
			hc = &http.Client{Transport: fileCAS{root: filepath.FromSlash(location.Path)}}
			baseURL = "http://local"
		}
	}
	if hc == nil {
		hc = &http.Client{}
	}
	return &CAS{baseURL: strings.TrimRight(baseURL, "/"), hc: hc, signer: signer}
}

func (c *CAS) blobPath(a artifact.Address) string {
	return "/blobs/sha256/" + a.Hex()
}

func (c *CAS) newReq(ctx context.Context, method string, a artifact.Address, body io.Reader) (*http.Request, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	path := c.blobPath(a)
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.signer != nil {
		if err := c.signer.SignCAS(req, method, path); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// casError distinguishes CAS failure modes so the loop can map them to the right
// runner verb (release{cas_unreachable|cas_miss|integrity}).
type casError struct {
	kind casErrKind
	err  error
}

type casErrKind int

const (
	casUnreachable casErrKind = iota
	casMiss
	casIntegrity
	casOther
)

func (e *casError) Error() string { return fmt.Sprintf("cas(%d): %v", e.kind, e.err) }

// casKindForStatus classifies a non-200, non-404 CAS response.
//
// Everything that was not 404 used to fall to casOther, which the loop maps to
// release(cas_unreachable). That was survivable only because the dispatcher now
// treats cas_unreachable as transient — but the statuses still deserve to be told
// apart: 429 and 503 are explicitly "come back later" from a healthy service, and
// 5xx is a server fault, so all of them are the plane being busy or broken rather
// than anything about this job. A persistent 403 is deliberately NOT laundered into
// a retriable class here: that is a genuine authorization denial, and retrying it
// only burns the fleet. The honest fix for a timing-out authorizer is for the PEP to
// answer 503 (unavailable) instead of 403 (denied), not for the runner to guess.
func casKindForStatus(status int) casErrKind {
	switch {
	case status == http.StatusTooManyRequests, status == http.StatusServiceUnavailable:
		return casUnreachable
	case status >= 500:
		return casUnreachable
	default:
		return casOther
	}
}

// GetToFile streams a blob to destPath, hashing en route, and verifies the
// result against the requested address. A mismatch is an integrity failure.
func (c *CAS) GetToFile(ctx context.Context, a artifact.Address, destPath string) (int64, error) {
	req, err := c.newReq(ctx, http.MethodGet, a, nil)
	if err != nil {
		return 0, &casError{casOther, err}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, &casError{casUnreachable, err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, &casError{casMiss, fmt.Errorf("blob %s not found", a)}
	}
	if resp.StatusCode != http.StatusOK {
		return 0, &casError{casKindForStatus(resp.StatusCode), fmt.Errorf("GET %s: status %d", a, resp.StatusCode)}
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return 0, &casError{casOther, err}
	}
	f, err := os.Create(destPath)
	if err != nil {
		return 0, &casError{casOther, err}
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if err != nil {
		return 0, &casError{casUnreachable, fmt.Errorf("stream %s: %w", a, err)}
	}
	if closeErr != nil {
		return 0, &casError{casOther, closeErr}
	}
	got := artifact.Address("sha256:" + hex.EncodeToString(h.Sum(nil)))
	if got != a {
		_ = os.Remove(destPath)
		return 0, &casError{casIntegrity, fmt.Errorf("integrity: got %s want %s", got, a)}
	}
	return n, nil
}

// GetBytes fetches a small blob (e.g. an invocation or manifest) and verifies it.
func (c *CAS) GetBytes(ctx context.Context, a artifact.Address) ([]byte, error) {
	req, err := c.newReq(ctx, http.MethodGet, a, nil)
	if err != nil {
		return nil, &casError{casOther, err}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &casError{casUnreachable, err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, &casError{casMiss, fmt.Errorf("blob %s not found", a)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &casError{casOther, fmt.Errorf("GET %s: status %d", a, resp.StatusCode)}
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &casError{casUnreachable, err}
	}
	if !a.Matches(b) {
		return nil, &casError{casIntegrity, fmt.Errorf("integrity: bytes do not match %s", a)}
	}
	return b, nil
}

// Head reports whether a blob exists and its size.
func (c *CAS) Head(ctx context.Context, a artifact.Address) (bool, int64, error) {
	req, err := c.newReq(ctx, http.MethodHead, a, nil)
	if err != nil {
		return false, 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return false, 0, &casError{casUnreachable, err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, 0, &casError{casOther, fmt.Errorf("HEAD %s: status %d", a, resp.StatusCode)}
	}
	size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	return true, size, nil
}

// PutFile uploads a file, addressed by its content hash (idempotent: an existing
// address is a no-op). Returns the address and size.
func (c *CAS) PutFile(ctx context.Context, path string) (artifact.Address, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	addr, err := hashFile(path)
	if err != nil {
		return "", 0, err
	}
	// Idempotent: skip the upload if the store already holds these exact bytes.
	if exists, _, err := c.Head(ctx, addr); err == nil && exists {
		return addr, fi.Size(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	req, err := c.newReq(ctx, http.MethodPut, addr, f)
	if err != nil {
		return "", 0, err
	}
	req.ContentLength = fi.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", 0, &casError{casUnreachable, err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", 0, &casError{casOther, fmt.Errorf("PUT %s: status %d", addr, resp.StatusCode)}
	}
	return addr, fi.Size(), nil
}

// PutBytes uploads a byte slice, addressed by content hash.
func (c *CAS) PutBytes(ctx context.Context, b []byte) (artifact.Address, error) {
	addr := artifact.ComputeAddress(b)
	if exists, _, err := c.Head(ctx, addr); err == nil && exists {
		return addr, nil
	}
	req, err := c.newReq(ctx, http.MethodPut, addr, strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	req.ContentLength = int64(len(b))
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", &casError{casUnreachable, err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", &casError{casOther, fmt.Errorf("PUT %s: status %d", addr, resp.StatusCode)}
	}
	return addr, nil
}

// LayoutInputs materializes an invocation's inputs under workdir/inputs/, one
// file per blob and an expanded tree per manifest, verifying every blob and
// re-checking every path against the traversal guard.
func (c *CAS) LayoutInputs(ctx context.Context, workdir string, inv *artifact.Invocation) error {
	inputsRoot := filepath.Join(workdir, "inputs")
	for name, in := range inv.Inputs {
		switch in.Kind {
		case artifact.KindBlob:
			dest := filepath.Join(inputsRoot, name)
			if _, err := c.GetToFile(ctx, in.Address, dest); err != nil {
				return err
			}
		case artifact.KindManifest:
			mb, err := c.GetBytes(ctx, in.Address)
			if err != nil {
				return err
			}
			var m artifact.Manifest
			if err := json.Unmarshal(mb, &m); err != nil {
				return &casError{casIntegrity, fmt.Errorf("manifest %s: %w", in.Address, err)}
			}
			if err := m.Validate(); err != nil {
				return &casError{casIntegrity, err}
			}
			base := filepath.Join(inputsRoot, name)
			for _, e := range m.Entries {
				// Re-check the traversal guard (schema is not trusted alone) and
				// confirm the joined path stays under the input's directory.
				if err := artifact.ValidateRelPath(e.Path); err != nil {
					return &casError{casIntegrity, err}
				}
				dest := filepath.Join(base, filepath.FromSlash(e.Path))
				if !within(base, dest) {
					return &casError{casIntegrity, fmt.Errorf("manifest path escapes input dir: %q", e.Path)}
				}
				if _, err := c.GetToFile(ctx, e.Address, dest); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("input %q: unknown kind %q", name, in.Kind)
		}
	}
	return nil
}

// within reports whether path is inside base (defense in depth on top of the
// relative-path guard).
func within(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func hashFile(path string) (artifact.Address, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return artifact.Address("sha256:" + hex.EncodeToString(h.Sum(nil))), nil
}
