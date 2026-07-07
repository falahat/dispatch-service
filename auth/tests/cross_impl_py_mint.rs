//! Cross-implementation proof: a phone credential **minted by easy-podcast
//! (biscuit-python)** AND a per-request **DPoP proof signed by easy-podcast
//! (joserfc)** are both accepted by this Rust PEP — closing two version-skew risks
//! in one committed vector:
//!
//!  1. biscuit-python ↔ biscuit-auth: the Biscuit itself crosses the language
//!     boundary and must parse + authorize under this `biscuit-auth` version.
//!  2. joserfc ↔ jsonwebtoken: the DPoP proof JWT (EdDSA, embedded OKP jwk) the app
//!     signs must verify under this `jsonwebtoken` version — the browser (`jose`) and
//!     Python (`joserfc`) signers agree with the PEP by the JWS/JWK standard, and
//!     this is the automated guard that the standard holds end to end.
//!
//! The fixture `tests/vectors/py_mint_dpop.json` is emitted by easy-podcast's
//! `tests/vectors/gen_plane_pop_vector.py`: it mints a full phone credential with the
//! isolated signer and signs a `POST /sync` DPoP proof. This test runs the WHOLE
//! `verify_http_dpop()` path against it. If it ever fails, easy-podcast is emitting a
//! token or proof this PEP rejects — every phone would fail live. The plane's mint +
//! DPoP schema (`cred.rs` / `dpop.rs`) is the source of truth; the app must match it.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::PublicKey;
use dispatch_auth::cred::{verify_http_dpop, DpopHttpRequest};
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::revocation::RevocationStore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The committed vector — easy-podcast's biscuit-python mint + joserfc DPoP proof.
#[derive(Deserialize)]
struct PyVector {
    issuer_public_hex: String,
    biscuit_b64: String,
    pubkey_hex: String,
    method: String,
    htu: String,
    body_b64: String,
    iat_s: i64,
    right: String,
    proof_jwt: String,
}

fn load_vector() -> PyVector {
    serde_json::from_str(include_str!("vectors/py_mint_dpop.json"))
        .expect("parse py_mint_dpop.json")
}

/// The issuer PUBLIC key recorded in the vector — the root the PEP parses against.
fn root_pub(v: &PyVector) -> PublicKey {
    PublicKey::from_bytes(&hex::decode(&v.issuer_public_hex).expect("issuer hex"))
        .expect("issuer public key")
}

fn body(v: &PyVector) -> Vec<u8> {
    STANDARD.decode(&v.body_b64).expect("body base64")
}

/// The `DpopHttpRequest` the PEP builds for this request, with `right` overridable
/// to isolate the capability check and `body` overridable to isolate the body binding.
fn dreq(v: &PyVector, right: &str, body: &[u8]) -> DpopHttpRequest {
    DpopHttpRequest {
        method: v.method.clone(),
        htu: v.htu.clone(),
        right: right.to_string(),
        biscuit_b64: v.biscuit_b64.clone(),
        proof_jwt: v.proof_jwt.clone(),
        body_sha256: Sha256::digest(body).into(),
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
fn python_minted_biscuit_and_dpop_proof_pass_the_rust_pep() {
    // THE proof: a biscuit-python Biscuit + a joserfc DPoP proof pass the full Rust
    // verify_http_dpop() — JWS signature (EdDSA/OKP jwk) + htm/htu/ath/content-digest
    // binding + Biscuit signature + `allow if right("sync")` + freshness.
    let v = load_vector();
    let (_d, nonces, revocations) = stores();
    let now_ms = v.iat_s * 1000; // freshness holds: iat == now
    let id = verify_http_dpop(
        &root_pub(&v),
        &nonces,
        &revocations,
        now_ms,
        &dreq(&v, &v.right, &body(&v)),
        true,
    )
    .expect("python-minted credential + proof must verify under the Rust PEP");
    assert_eq!(id.id, v.pubkey_hex);
}

#[test]
fn python_minted_biscuit_denied_for_a_right_it_lacks() {
    // Negative control: the credential presented for a right it does not carry is
    // denied at authorization. The right is server-side (not in the proof), so the
    // proof stays valid — this isolates the capability gate.
    let v = load_vector();
    let (_d, nonces, revocations) = stores();
    let now_ms = v.iat_s * 1000;
    assert!(
        verify_http_dpop(
            &root_pub(&v),
            &nonces,
            &revocations,
            now_ms,
            &dreq(&v, "lease", &body(&v)),
            true
        )
        .is_err(),
        "a phone credential must be denied a right it does not carry",
    );
}

#[test]
fn python_dpop_proof_denied_when_body_tampered() {
    // The proof's content-digest binds sha256(body): delivering different bytes than
    // were signed must fail — the same integrity guarantee, across the mint's language
    // boundary.
    let v = load_vector();
    let (_d, nonces, revocations) = stores();
    let now_ms = v.iat_s * 1000;
    assert!(
        verify_http_dpop(
            &root_pub(&v),
            &nonces,
            &revocations,
            now_ms,
            &dreq(&v, &v.right, b"a different body than was signed"),
            true,
        )
        .is_err(),
        "a tampered body must break the DPoP content-digest",
    );
}
