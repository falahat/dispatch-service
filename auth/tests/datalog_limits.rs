//! Adversarial: the Datalog DoS guard must be DETERMINISTIC, not the wall clock.
//!
//! Background. `AuthorizerLimits::max_time` is measured as `Instant` elapsed across the whole
//! authorize call, so with biscuit's 1 ms default a structurally-valid credential's verdict
//! became a function of host CPU scheduling: during the 2026-07 transcribe backfill that
//! pegged all 24 cores, trivial authorizes were preempted past 1 ms and the PEP fail-closed
//! 403'd healthy runner frames. Widening that budget fixed the brownout, but a wall-clock
//! budget can never be the real guard — it is the one limit an attacker does not control and
//! a busy host does.
//!
//! So the guard is `max_facts` / `max_iterations`, which are functions of TOKEN CONTENT. These
//! tests pin both halves of that claim: a hostile fact-bomb is refused, and it is refused for a
//! deterministic reason rather than by running out of clock.
//!
//! Attenuation needs no root key (see `attenuate_for_lease`), so appending blocks is squarely
//! within a token holder's power — this is a real capability, not a hypothetical.
//!
//! HAND-WRITTEN.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use dispatch_auth::canonical::Op;
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::revocation::RevocationStore;
use dispatch_auth::{attenuate_for_lease, mint, verify, AuthedRequest, MintParams};
use ed25519_dalek::{Signer, SigningKey};

const NOW_MS: i64 = 1_700_000_000_000;

fn stores() -> (tempfile::TempDir, NonceStore, RevocationStore) {
    let dir = tempfile::tempdir().unwrap();
    let nonces =
        NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();
    let revocations = RevocationStore::open(dir.path().join("revocations.json")).unwrap();
    (dir, nonces, revocations)
}

/// A signed cas_get request for `token`, so the PoP is valid and the ONLY thing under
/// test is the Datalog evaluation.
fn signed_request(sk: &SigningKey, pubkey_hex: &str, token: &str, nonce: &str) -> AuthedRequest {
    let op = Op::Cas {
        method: "GET".into(),
        path: "/cas/sha256/aa".into(),
    };
    let canonical = op.canonical(nonce, NOW_MS);
    let sig = sk.sign(canonical.as_bytes());
    AuthedRequest {
        op,
        biscuit_b64: token.to_string(),
        pubkey_hex: pubkey_hex.to_string(),
        nonce_b64: nonce.to_string(),
        ts_ms: NOW_MS,
        pop_sig_b64: STANDARD.encode(sig.to_bytes()),
        required_lanes: vec![],
        address_hex: Some("aa".into()),
    }
}

fn keypair() -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pubkey_hex)
}

#[test]
fn a_fact_bomb_attenuation_is_refused() {
    // A token holder appends a block carrying far more facts than any real lease scope.
    // The deterministic ceiling must stop it — on an idle machine, where a wall-clock
    // budget would NOT have been exceeded and would therefore have let it through.
    let root = biscuit_auth::KeyPair::new();
    let (sk, pubkey_hex) = keypair();
    let base = mint(
        &root,
        &MintParams {
            pubkey_hex: pubkey_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec!["embed".into()],
        },
    )
    .unwrap();

    // "aa" is INCLUDED so the address check itself PASSES: the only thing left that can
    // deny this request is the resource ceiling, not a scope miss.
    let mut bomb: Vec<String> = vec!["aa".to_string()];
    bomb.extend((0..5000).map(|i| format!("{i:064x}")));
    let hostile = attenuate_for_lease(&base, &root.public(), &bomb, NOW_MS + 60_000).unwrap();

    let (_d, nonces, revocations) = stores();
    let err = verify(
        &root.public(),
        &nonces,
        &revocations,
        NOW_MS,
        &signed_request(&sk, &pubkey_hex, &hostile, "bomb-nonce"),
        true,
    )
    .expect_err("a fact bomb must be refused, not evaluated to completion");

    // Refused on SIZE, before any parse/verify/evaluate work is spent on it — and never on
    // a timeout, so the verdict is identical on a pegged host and an idle one.
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains("too large"),
        "a 508 KiB credential must be refused at the size boundary, got: {msg}"
    );
    assert!(
        !msg.contains("timeout"),
        "the refusal must be deterministic, not clock-dependent: {msg}"
    );
}

#[test]
fn an_ordinary_credential_still_authorizes() {
    // The necessary companion: ceilings tight enough to stop a bomb must still leave a real
    // credential — a pubkey fact, one right, one lane, plus the request's checks — far inside
    // them. Without this, "deny everything" would pass the test above.
    let root = biscuit_auth::KeyPair::new();
    let (sk, pubkey_hex) = keypair();
    let token = mint(
        &root,
        &MintParams {
            pubkey_hex: pubkey_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec!["embed".into()],
        },
    )
    .unwrap();
    let scoped =
        attenuate_for_lease(&token, &root.public(), &["aa".to_string()], NOW_MS + 60_000).unwrap();

    let (_d, nonces, revocations) = stores();
    let id = verify(
        &root.public(),
        &nonces,
        &revocations,
        NOW_MS,
        &signed_request(&sk, &pubkey_hex, &scoped, "ok-nonce"),
        true,
    )
    .expect("a normal lease-scoped credential must still authorize");
    assert_eq!(id.id, pubkey_hex);
}
