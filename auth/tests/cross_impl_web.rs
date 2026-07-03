//! Cross-implementation proof: the browser signer (`client-web`, TypeScript +
//! libsodium) and this Rust verifier agree on the `http/v0` canonical string and
//! the Ed25519 proof-of-possession, byte-for-byte.
//!
//! The fixture `tests/vectors/web_pop.json` is produced by
//! `client-web/scripts/gen-vector.mjs`: a FIXED 32-byte seed, a fixed
//! method/path/body/nonce/ts, and the resulting pubkey + pop the TS signer
//! emitted. This test asserts two independent things:
//!
//!  (a) the TS-produced pop + pubkey are ACCEPTED by the plane's verifier — both
//!      the low-level `pop::verify_pop` and the full `verify()` path (Biscuit +
//!      capability + freshness), exactly as the HTTP PEP would call it; and
//!
//!  (b) Ed25519 is deterministic, so signing the SAME canonical with the SAME key
//!      in Rust yields the EXACT same signature bytes as the TS pop. This pins the
//!      canonical bytes and the key derivation on both sides — a mismatch anywhere
//!      (a stray space, a different ts format, url-safe vs standard base64, seed
//!      handling) would break the equality.
//!
//! If this test ever fails, the TS signer is what must change: `canonical.rs` /
//! `cred.rs` are the source of truth.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::KeyPair;
use dispatch_auth::cred::{mint, verify, AuthedRequest, MintParams};
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::pop;
use dispatch_auth::Op;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;

/// The committed cross-impl vector, emitted by the TypeScript signer.
#[derive(Deserialize)]
struct WebVector {
    seed_hex: String,
    method: String,
    path: String,
    body_sha256_hex: String,
    nonce: String,
    ts_ms: i64,
    canonical: String,
    pubkey_hex: String,
    pop_b64: String,
}

fn load_vector() -> WebVector {
    let raw = include_str!("vectors/web_pop.json");
    serde_json::from_str(raw).expect("parse web_pop.json")
}

/// The right the PEP would resolve for this route from its route table.
const RIGHT: &str = "upsert";

/// Rebuild the exact `Op::Http` the PEP builds for this request.
fn op_for(v: &WebVector) -> Op {
    Op::Http {
        method: v.method.clone(),
        path: v.path.clone(),
        right: RIGHT.to_string(),
        body_sha256_hex: v.body_sha256_hex.clone(),
    }
}

#[test]
fn ts_canonical_matches_rust_canonical() {
    // The PEP never trusts a client-supplied canonical string — it rebuilds it.
    // Prove the rebuilt string equals what the TS side signed, so the two agree
    // on every byte (tag, spacing, uppercase method, body-hash, nonce, ts).
    let v = load_vector();
    let rebuilt = op_for(&v).canonical(&v.nonce, v.ts_ms);
    assert_eq!(rebuilt, v.canonical, "canonical string mismatch across impls");
}

#[test]
fn ts_pop_verifies_with_rust_verify_pop() {
    // (a, low level) The TS pop is a valid Ed25519 signature over the canonical
    // under the TS pubkey — decoded with the STANDARD (padded) base64 engine, the
    // same one `cred.rs` uses. A url-safe pop would fail to decode/verify here.
    let v = load_vector();
    let pubkey = hex::decode(&v.pubkey_hex).expect("pubkey hex");
    let sig = STANDARD.decode(&v.pop_b64).expect("pop is standard base64");
    let rebuilt = op_for(&v).canonical(&v.nonce, v.ts_ms);
    pop::verify_pop(&pubkey, &rebuilt, &sig).expect("TS pop must verify in Rust");
}

#[test]
fn ts_pop_bytes_equal_rust_signature() {
    // (b) Ed25519 is deterministic: the same seed + same message => the same 64
    // signature bytes. Derive the key from the vector's seed the way the plane
    // does (`SigningKey::from_bytes`), sign the rebuilt canonical, and require the
    // bytes to EQUAL the TS pop. This is the strongest cross-impl assertion: it
    // pins key derivation AND the canonical bytes on both sides.
    let v = load_vector();
    let seed: [u8; 32] = hex::decode(&v.seed_hex)
        .expect("seed hex")
        .try_into()
        .expect("seed is 32 bytes");
    let sk = SigningKey::from_bytes(&seed);

    // The derived pubkey must match what TS put on the wire.
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        v.pubkey_hex,
        "seed-derived pubkey mismatch across impls",
    );

    let rebuilt = op_for(&v).canonical(&v.nonce, v.ts_ms);
    let rust_sig = STANDARD.encode(sk.sign(rebuilt.as_bytes()).to_bytes());
    assert_eq!(
        rust_sig, v.pop_b64,
        "deterministic Ed25519 signature differs across impls",
    );
}

#[test]
fn ts_request_passes_full_verify() {
    // (a, end to end) Feed the TS-produced fields through the WHOLE `verify()`
    // path the HTTP PEP runs: PoP + Biscuit signature + capability authorization +
    // freshness. Mint a Biscuit (as the plane signer would) binding the TS pubkey
    // and the required right, and set `now` to the vector's ts so freshness holds.
    let v = load_vector();
    let root = KeyPair::new();
    let biscuit = mint(
        &root,
        &MintParams {
            pubkey_hex: v.pubkey_hex.clone(),
            rights: vec![RIGHT.to_string()],
            lanes: vec![],
        },
    )
    .expect("mint biscuit");

    let dir = tempfile::tempdir().unwrap();
    let nonces =
        NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();

    let areq = AuthedRequest {
        op: op_for(&v),
        biscuit_b64: biscuit,
        pubkey_hex: v.pubkey_hex.clone(),
        nonce_b64: v.nonce.clone(),
        ts_ms: v.ts_ms,
        pop_sig_b64: v.pop_b64.clone(),
        required_lanes: vec![],
        address_hex: None,
    };

    // Header-auth semantics: single-use. `now == ts` so it is fresh.
    let id = verify(&root.public(), &nonces, v.ts_ms, &areq, true)
        .expect("TS request must pass the full verify path");
    assert_eq!(id.id, v.pubkey_hex);
}

#[test]
fn wrong_right_denies_the_ts_request() {
    // Negative control: the same valid PoP + a Biscuit lacking the required right
    // is denied at authorization, proving the accept above is a real capability
    // check and not a rubber stamp.
    let v = load_vector();
    let root = KeyPair::new();
    let biscuit = mint(
        &root,
        &MintParams {
            pubkey_hex: v.pubkey_hex.clone(),
            rights: vec!["some_other_right".to_string()],
            lanes: vec![],
        },
    )
    .expect("mint biscuit");

    let dir = tempfile::tempdir().unwrap();
    let nonces =
        NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();

    let areq = AuthedRequest {
        op: op_for(&v),
        biscuit_b64: biscuit,
        pubkey_hex: v.pubkey_hex.clone(),
        nonce_b64: v.nonce.clone(),
        ts_ms: v.ts_ms,
        pop_sig_b64: v.pop_b64.clone(),
        required_lanes: vec![],
        address_hex: None,
    };

    assert!(
        verify(&root.public(), &nonces, v.ts_ms, &areq, true).is_err(),
        "a Biscuit without the required right must be denied",
    );
}
