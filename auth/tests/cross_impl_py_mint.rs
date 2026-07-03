//! Cross-implementation proof: a phone credential **minted by easy-podcast (biscuit-python)** is
//! accepted by this Rust `biscuit-auth` PEP verifier — closing the biscuit-python ↔ biscuit-auth
//! version-skew risk.
//!
//! `cross_impl_web.rs` proves the browser's PoP but mints its Biscuit in Rust. Here the **Biscuit
//! itself** crosses the language boundary: the fixture `tests/vectors/py_mint_pop.json` is emitted
//! by easy-podcast's `tests/vectors/gen_plane_pop_vector.py`, where the app mints a full phone
//! credential (rights sync/audio/upsert/ping) with its isolated signer and signs a `POST /sync`
//! PoP. This test parses that Biscuit against the recorded issuer public key and runs the WHOLE
//! `verify()` path. If it ever fails, easy-podcast's biscuit-python is emitting a token this
//! biscuit-auth version rejects — every phone would fail at the live PEP. The plane's canonical /
//! mint schema (`canonical.rs` / `cred.rs`) is the source of truth; the app's mint must match it.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::PublicKey;
use dispatch_auth::cred::{verify, AuthedRequest};
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::revocation::RevocationStore;
use dispatch_auth::Op;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The committed vector — easy-podcast's biscuit-python mint + plane PoP (extra fields ignored).
#[derive(Deserialize)]
struct PyVector {
    issuer_public_hex: String,
    biscuit_b64: String,
    pubkey_hex: String,
    nonce_b64: String,
    ts_ms: i64,
    pop_b64: String,
    method: String,
    path: String,
    body_b64: String,
    right: String,
}

fn load_vector() -> PyVector {
    serde_json::from_str(include_str!("vectors/py_mint_pop.json")).expect("parse py_mint_pop.json")
}

/// The issuer PUBLIC key recorded in the vector — the root the PEP parses the Biscuit against.
fn root_pub(v: &PyVector) -> PublicKey {
    PublicKey::from_bytes(&hex::decode(&v.issuer_public_hex).expect("issuer hex"))
        .expect("issuer public key")
}

/// The `Op::Http` the PEP builds for this request, with `right` overridable to isolate the
/// capability check. The body hash is recomputed from the vector's body — exactly as the PEP does.
fn op_for(v: &PyVector, right: &str, body: &[u8]) -> Op {
    Op::Http {
        method: v.method.clone(),
        path: v.path.clone(),
        right: right.to_string(),
        body_sha256_hex: hex::encode(Sha256::digest(body)),
    }
}

fn areq(v: &PyVector, op: Op) -> AuthedRequest {
    AuthedRequest {
        op,
        biscuit_b64: v.biscuit_b64.clone(),
        pubkey_hex: v.pubkey_hex.clone(),
        nonce_b64: v.nonce_b64.clone(),
        ts_ms: v.ts_ms,
        pop_sig_b64: v.pop_b64.clone(),
        required_lanes: vec![],
        address_hex: None,
    }
}

fn stores() -> (tempfile::TempDir, NonceStore, RevocationStore) {
    let dir = tempfile::tempdir().unwrap();
    let nonces =
        NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();
    let revocations = RevocationStore::open(dir.path().join("revocations.json")).unwrap();
    (dir, nonces, revocations)
}

#[test]
fn python_minted_phone_biscuit_passes_the_rust_pep() {
    // THE proof: a Biscuit minted by easy-podcast's biscuit-python signer (plane-schema facts,
    // bound to the phone key) parses against the recorded issuer public key and passes the full
    // Rust verify() — PoP + Biscuit signature + `allow if right("sync")` + freshness.
    let v = load_vector();
    let body = STANDARD.decode(&v.body_b64).expect("body base64");
    let (_d, nonces, revocations) = stores();
    let req = areq(&v, op_for(&v, &v.right, &body));
    let id = verify(&root_pub(&v), &nonces, &revocations, v.ts_ms, &req, true)
        .expect("python-minted credential must verify under the Rust PEP");
    assert_eq!(id.id, v.pubkey_hex);
}

#[test]
fn python_minted_biscuit_denied_for_a_right_it_lacks() {
    // Negative control: the credential (sync/audio/upsert/ping) presented for a WORKER right it does
    // not carry is denied. The right is NOT in the canonical, so the PoP stays valid — this isolates
    // the authorization check, proving the accept above is a real capability gate, not a rubber stamp.
    let v = load_vector();
    let body = STANDARD.decode(&v.body_b64).expect("body base64");
    let (_d, nonces, revocations) = stores();
    let req = areq(&v, op_for(&v, "lease", &body));
    assert!(
        verify(&root_pub(&v), &nonces, &revocations, v.ts_ms, &req, true).is_err(),
        "a phone credential must be denied a right it does not carry",
    );
}

#[test]
fn python_minted_biscuit_denied_when_body_tampered() {
    // The PoP binds sha256(body): delivering different bytes than were signed must fail verify() —
    // the same integrity guarantee, proven across the mint's language boundary.
    let v = load_vector();
    let (_d, nonces, revocations) = stores();
    let req = areq(&v, op_for(&v, &v.right, b"a different body than was signed"));
    assert!(
        verify(&root_pub(&v), &nonces, &revocations, v.ts_ms, &req, true).is_err(),
        "a tampered body must break the PoP",
    );
}
