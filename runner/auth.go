package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Credential is the runner's on-disk credential: the opaque Biscuit token, the
// Ed25519 public key it binds (hex), and the 32-byte private seed the runner
// signs proofs-of-possession with. The runner never needs a Biscuit library —
// the token is carried verbatim; only the PoP is computed here.
type Credential struct {
	Biscuit   string `json:"biscuit"`    // base64 Biscuit token
	PubkeyHex string `json:"pubkey_hex"` // hex Ed25519 public key
	SeedB64   string `json:"seed_b64"`   // base64 of the 32-byte Ed25519 seed
}

// LoadCredential reads a credential file.
func LoadCredential(path string) (*Credential, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	if c.Biscuit == "" || c.PubkeyHex == "" || c.SeedB64 == "" {
		return nil, fmt.Errorf("credential: incomplete (need biscuit, pubkey_hex, seed_b64)")
	}
	return &c, nil
}

// GenerateKeypair mints a fresh Ed25519 seed and returns (seedB64, pubkeyHex).
// The operator enrolls pubkeyHex with the signer to obtain the Biscuit.
func GenerateKeypair() (seedB64, pubkeyHex string, err error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(seed), hex.EncodeToString(pub), nil
}

// popSigner turns a credential into the CAS Signer and dispatcher FrameWrapper.
// The canonical strings mirror the Rust PEP exactly (canonical.rs).
type popSigner struct {
	cred *Credential
	priv ed25519.PrivateKey
}

// NewPoPSigner builds the auth adapter from a credential.
func NewPoPSigner(c *Credential) (*popSigner, error) {
	seed, err := base64.StdEncoding.DecodeString(c.SeedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("credential: bad seed")
	}
	return &popSigner{cred: c, priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func nowMS() int64 { return time.Now().UnixMilli() }

func newNonce() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// SignCAS attaches Biscuit + PoP headers for a CAS request (CAS.md canonical).
func (p *popSigner) SignCAS(req *http.Request, method, casPath string) error {
	nonce := newNonce()
	ts := nowMS()
	canonical := fmt.Sprintf("cas/v0 %s %s %s %d", method, casPath, nonce, ts)
	sig := ed25519.Sign(p.priv, []byte(canonical))
	req.Header.Set("X-Dispatch-Biscuit", p.cred.Biscuit)
	req.Header.Set("X-Dispatch-Pubkey", p.cred.PubkeyHex)
	req.Header.Set("X-Dispatch-Nonce", nonce)
	req.Header.Set("X-Dispatch-Ts", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Dispatch-Pop", base64.StdEncoding.EncodeToString(sig))
	return nil
}

// authFrame is the outer wrapper sent to the PEP on the runner surface.
type authFrame struct {
	B string `json:"b"` // biscuit
	K string `json:"k"` // pop pubkey hex
	N string `json:"n"` // nonce b64
	T int64  `json:"t"` // ts ms
	S string `json:"s"` // pop sig b64
	M string `json:"m"` // inner frame bytes, b64
}

// Wrap authenticates an outgoing runner frame for the PEP: the PoP signs
// `dispatch/v0 <verb> <sha256hex(inner)> <nonce> <ts>` (frame_proxy.rs).
func (p *popSigner) Wrap(typ string, inner []byte) ([]byte, error) {
	nonce := newNonce()
	ts := nowMS()
	sum := sha256.Sum256(inner)
	canonical := fmt.Sprintf("dispatch/v0 %s %s %s %d", typ, hex.EncodeToString(sum[:]), nonce, ts)
	sig := ed25519.Sign(p.priv, []byte(canonical))
	af := authFrame{
		B: p.cred.Biscuit,
		K: p.cred.PubkeyHex,
		N: nonce,
		T: ts,
		S: base64.StdEncoding.EncodeToString(sig),
		M: base64.StdEncoding.EncodeToString(inner),
	}
	return json.Marshal(af)
}
