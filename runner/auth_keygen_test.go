package runner

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestKeygenSealRoundTrip is the enrollment round-trip: keygen writes a keypair
// (seed on disk only, 0600, no biscuit -> not yet a usable credential); seal folds
// a minted biscuit in; the result loads and yields a PoP signer.
func TestKeygenSealRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runner.json")

	pub, err := WriteKeypair(path)
	if err != nil {
		t.Fatalf("WriteKeypair: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("keypair perms = %o, want 0600", got)
		}
	}

	// An unsealed keypair is NOT a usable credential (no biscuit) — fail closed.
	if _, err := LoadCredential(path); err == nil {
		t.Fatal("LoadCredential accepted an unsealed keypair")
	}

	// The printed pubkey matches the on-disk seed and is written to the file.
	raw, _ := os.ReadFile(path)
	var kp Credential
	if err := json.Unmarshal(raw, &kp); err != nil {
		t.Fatal(err)
	}
	if kp.Biscuit != "" {
		t.Fatalf("keypair file already carries a biscuit: %q", kp.Biscuit)
	}
	seed, err := base64.StdEncoding.DecodeString(kp.SeedB64)
	if err != nil {
		t.Fatal(err)
	}
	derived := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if pub != derived || kp.PubkeyHex != pub {
		t.Fatalf("pubkey mismatch: printed=%s file=%s derived=%s", pub, kp.PubkeyHex, derived)
	}

	// Seal (leading/trailing whitespace on the piped biscuit must be trimmed).
	const biscuit = "En0KEwoDYXBwGAMiCQoHCAoSAwiACBIkCAASIA"
	if err := SealCredential(path, "\n  "+biscuit+"  \n"); err != nil {
		t.Fatalf("SealCredential: %v", err)
	}
	c, err := LoadCredential(path)
	if err != nil {
		t.Fatalf("LoadCredential after seal: %v", err)
	}
	if c.Biscuit != biscuit || c.PubkeyHex != pub || c.SeedB64 != kp.SeedB64 {
		t.Fatalf("sealed credential fields wrong: %+v", c)
	}
	if _, err := NewPoPSigner(c); err != nil {
		t.Fatalf("NewPoPSigner on sealed cred: %v", err)
	}
}

// TestSealFailsClosed: seal refuses an empty biscuit or a keypair missing its seed,
// rather than writing a broken credential.
func TestSealFailsClosed(t *testing.T) {
	dir := t.TempDir()

	kp := filepath.Join(dir, "kp.json")
	if _, err := WriteKeypair(kp); err != nil {
		t.Fatal(err)
	}
	if err := SealCredential(kp, "   \n"); err == nil {
		t.Fatal("seal accepted an empty biscuit")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"pubkey_hex":"ab"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SealCredential(bad, "a-biscuit"); err == nil {
		t.Fatal("seal accepted a keypair with no seed")
	}
}
