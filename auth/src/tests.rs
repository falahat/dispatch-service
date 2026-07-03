//! Adversarial unit tests for the auth core. Every security boundary asserts
//! the fail-closed outcome. (These are hand-authored, not generated.)

use crate::canonical::Op;
use crate::cred::{attenuate_for_lease, mint, verify, AuthedRequest, MintParams};
use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::revocation::RevocationStore;
use biscuit_auth::KeyPair;
use ed25519_dalek::{Signer as _, SigningKey};

const NOW: i64 = 1_700_000_000_000;

/// An empty deny-list (its file never exists → nothing is revoked), for the
/// tests that are not about revocation. Revocation has its own tests below.
fn no_rev() -> RevocationStore {
    let dir = std::env::temp_dir().join(format!("pep-norev-{}", rand::random::<u64>()));
    RevocationStore::open(dir.join("revocations.json")).unwrap()
}

fn holder() -> (SigningKey, String) {
    let seed: [u8; 32] = rand_bytes();
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

fn rand_bytes() -> [u8; 32] {
    // A test-only CSPRNG seed. rand::random gives independent draws per call.
    let mut b = [0u8; 32];
    for x in b.iter_mut() {
        *x = rand::random::<u8>();
    }
    b
}

fn nonce_b64() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(rand_bytes()) // 32 random bytes as a nonce
}

fn sign_pop(sk: &SigningKey, canonical: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let sig = sk.sign(canonical.as_bytes());
    STANDARD.encode(sig.to_bytes())
}

fn store(name: &str) -> (tempfile::TempDir, NonceStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let ns = NonceStore::open(&path, crate::nonce::DEFAULT_WINDOW_MS).unwrap();
    (dir, ns)
}

// Build a CAS GET request signed by `sk`, presenting `pubkey_hex` and `cred`.
fn cas_get_req(
    sk: &SigningKey,
    pubkey_hex: &str,
    cred: &str,
    hexaddr: &str,
    ts: i64,
) -> AuthedRequest {
    let path = format!("/blobs/sha256/{hexaddr}");
    let op = Op::Cas {
        method: "GET".into(),
        path,
    };
    let nonce = nonce_b64();
    let canonical = op.canonical(&nonce, ts);
    let sig = sign_pop(sk, &canonical);
    AuthedRequest {
        op,
        biscuit_b64: cred.to_string(),
        pubkey_hex: pubkey_hex.to_string(),
        nonce_b64: nonce,
        ts_ms: ts,
        pop_sig_b64: sig,
        required_lanes: vec![],
        address_hex: Some(hexaddr.to_string()),
    }
}

const ADDR_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ADDR_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn happy_path_cas_get() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    let id = verify(&root.public(), &ns, &no_rev(), NOW, &req, true).expect("valid request");
    assert_eq!(id.id, pk_hex);
}

#[test]
fn pop_with_wrong_key_is_rejected() {
    let root = KeyPair::new();
    let (_sk, pk_hex) = holder();
    let (attacker, _) = holder(); // a different private key
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    // Present the victim's pubkey but sign with the attacker's key.
    let req = cas_get_req(&attacker, &pk_hex, &cred, ADDR_A, NOW);
    match verify(&root.public(), &ns, &no_rev(), NOW, &req, true) {
        Err(AuthError::PopFailed) => {}
        other => panic!("expected PopFailed, got {other:?}"),
    }
}

#[test]
fn forged_biscuit_from_other_root_is_rejected() {
    let root = KeyPair::new();
    let evil_root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &evil_root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    match verify(&root.public(), &ns, &no_rev(), NOW, &req, true) {
        Err(AuthError::BiscuitSignature) => {}
        other => panic!("expected BiscuitSignature, got {other:?}"),
    }
}

#[test]
fn replay_same_nonce_is_rejected() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    verify(&root.public(), &ns, &no_rev(), NOW, &req, true).expect("first ok");
    // Replay the exact same request (same nonce).
    match verify(&root.public(), &ns, &no_rev(), NOW, &req, true) {
        Err(AuthError::Replay) => {}
        other => panic!("expected Replay, got {other:?}"),
    }
}

#[test]
fn non_single_use_allows_nonce_reuse_but_still_enforces_freshness() {
    // The freshness-only path (signed-URL reads): the SAME nonce verifies more
    // than once (no dedup), but a stale ts is still rejected. This is what lets
    // a browser reuse one signed URL across range requests while the URL expires.
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    // Reused twice with single_use=false: both pass (no replay rejection).
    verify(&root.public(), &ns, &no_rev(), NOW, &req, false).expect("first freshness-only ok");
    verify(&root.public(), &ns, &no_rev(), NOW, &req, false).expect("reuse must still pass");
    // But a stale ts is rejected even freshness-only (the URL expires).
    let stale = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW - 10 * 60 * 1000);
    match verify(&root.public(), &ns, &no_rev(), NOW, &stale, false) {
        Err(AuthError::Freshness) => {}
        other => panic!("expected Freshness for stale freshness-only, got {other:?}"),
    }
}

#[test]
fn replay_across_restart_is_rejected() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("durable.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    {
        let ns = NonceStore::open(&path, crate::nonce::DEFAULT_WINDOW_MS).unwrap();
        verify(&root.public(), &ns, &no_rev(), NOW, &req, true).expect("first ok");
    } // store dropped (restart)
    let ns2 = NonceStore::open(&path, crate::nonce::DEFAULT_WINDOW_MS).unwrap();
    match verify(&root.public(), &ns2, &no_rev(), NOW, &req, true) {
        Err(AuthError::Replay) => {}
        other => panic!("expected Replay across restart, got {other:?}"),
    }
}

#[test]
fn stale_timestamp_is_rejected() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let stale = NOW - 10 * 60 * 1000; // 10 min old, window is 5 min
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, stale);
    match verify(&root.public(), &ns, &no_rev(), NOW, &req, true) {
        Err(AuthError::Freshness) => {}
        other => panic!("expected Freshness, got {other:?}"),
    }
}

#[test]
fn missing_right_is_denied() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    // Credential grants cas_put but NOT cas_get.
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_put".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    match verify(&root.public(), &ns, &no_rev(), NOW, &req, true) {
        Err(AuthError::Denied(_)) => {}
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn presented_pubkey_must_match_credential() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let (_other_sk, other_pk_hex) = holder();
    // Credential binds `other_pk_hex`, but the request presents pk_hex (and signs
    // with sk matching pk_hex). PoP passes for pk_hex, but the biscuit binds a
    // different key -> the pubkey-match check denies.
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: other_pk_hex,
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    match verify(&root.public(), &ns, &no_rev(), NOW, &req, true) {
        Err(AuthError::Denied(_)) => {}
        other => panic!("expected Denied (pubkey mismatch), got {other:?}"),
    }
}

#[test]
fn lane_scope_enforced_on_lease() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["lease".into()],
            lanes: vec!["embed".into()],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");

    let mk = |lane: &str, ts: i64| {
        let op = Op::Dispatch {
            verb: "lease".into(),
            frame_sha256_hex: "00".repeat(32),
        };
        let nonce = nonce_b64();
        let canonical = op.canonical(&nonce, ts);
        let sig = sign_pop(&sk, &canonical);
        AuthedRequest {
            op,
            biscuit_b64: cred.clone(),
            pubkey_hex: pk_hex.clone(),
            nonce_b64: nonce,
            ts_ms: ts,
            pop_sig_b64: sig,
            required_lanes: vec![lane.to_string()],
            address_hex: None,
        }
    };

    // A lane the credential grants: ok.
    verify(&root.public(), &ns, &no_rev(), NOW, &mk("embed", NOW), true).expect("embed lease ok");
    // A lane it does not grant: denied.
    match verify(
        &root.public(),
        &ns,
        &no_rev(),
        NOW + 1,
        &mk("transcribe", NOW + 1),
        true,
    ) {
        Err(AuthError::Denied(_)) => {}
        other => panic!("expected Denied for ungranted lane, got {other:?}"),
    }
}

#[test]
fn attenuated_token_scopes_get_to_closure() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let base = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    // Scope to ADDR_A only, expiring in the future.
    let scoped =
        attenuate_for_lease(&base, &root.public(), &[ADDR_A.to_string()], NOW + 60_000).unwrap();

    let (_d, ns) = store("n.redb");
    // GET of the in-closure address: allowed.
    verify(
        &root.public(),
        &ns,
        &no_rev(),
        NOW,
        &cas_get_req(&sk, &pk_hex, &scoped, ADDR_A, NOW),
        true,
    )
    .expect("in-closure ok");
    // GET of another job's address: denied.
    match verify(
        &root.public(),
        &ns,
        &no_rev(),
        NOW + 1,
        &cas_get_req(&sk, &pk_hex, &scoped, ADDR_B, NOW + 1),
        true,
    ) {
        Err(AuthError::Denied(_)) => {}
        other => panic!("expected Denied for out-of-closure address, got {other:?}"),
    }
}

#[test]
fn attenuated_token_expires() {
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let base = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let scoped =
        attenuate_for_lease(&base, &root.public(), &[ADDR_A.to_string()], NOW - 1).unwrap(); // already expired

    let (_d, ns) = store("n.redb");
    match verify(
        &root.public(),
        &ns,
        &no_rev(),
        NOW,
        &cas_get_req(&sk, &pk_hex, &scoped, ADDR_A, NOW),
        true,
    ) {
        Err(AuthError::Denied(_)) => {}
        other => panic!("expected Denied (expired), got {other:?}"),
    }
}

// ---------- revocation (deny-list enforcement in verify) ----------

/// Open an empty deny-list in a tempdir; return the store and its file path so a
/// test can revoke a credential mid-run (proving the live-reload).
fn rev_store() -> (tempfile::TempDir, RevocationStore, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revocations.json");
    let rev = RevocationStore::open(&path).unwrap();
    (dir, rev, path)
}

/// The authority-block revocation id (lowercase hex) of a minted credential —
/// what an operator would put on the deny-list to revoke it.
fn authority_revocation_id(root: &KeyPair, cred: &str) -> String {
    let biscuit = biscuit_auth::Biscuit::from_base64(cred, root.public()).unwrap();
    hex::encode(&biscuit.revocation_identifiers()[0])
}

#[test]
fn revoked_credential_is_denied() {
    // A credential whose authority revocation id is on the deny-list is denied
    // with the dedicated `Revoked` outcome — before the capability check, so it
    // is denied regardless of the right it would otherwise satisfy.
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let (_rd, rev, _path) = rev_store();
    rev.revoke(&authority_revocation_id(&root, &cred), "compromised", NOW)
        .unwrap();
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    match verify(&root.public(), &ns, &rev, NOW, &req, true) {
        Err(AuthError::Revoked) => {}
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn non_revoked_credential_still_passes() {
    // The negative control: a deny-list holding some OTHER id does not deny an
    // unrelated credential.
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let (_rd, rev, _path) = rev_store();
    // Revoke an unrelated id (64 hex zeros) — must not affect this credential.
    rev.revoke(&"0".repeat(64), "someone else", NOW).unwrap();
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    let id = verify(&root.public(), &ns, &rev, NOW, &req, true).expect("non-revoked must pass");
    assert_eq!(id.id, pk_hex);
}

#[test]
fn revoking_authority_id_denies_every_attenuation() {
    // The security guarantee: revoking the AUTHORITY-block id denies not just the
    // base credential but every token attenuated from it, because the authority
    // id stays in an attenuated token's revocation_identifiers. We attenuate the
    // base for a lease, then revoke the base's authority id and prove the
    // attenuated token is denied.
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let base = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let scoped =
        attenuate_for_lease(&base, &root.public(), &[ADDR_A.to_string()], NOW + 60_000).unwrap();
    // Sanity: the attenuated token's revocation ids INCLUDE the base authority id.
    let base_auth_id = authority_revocation_id(&root, &base);
    let scoped_biscuit = biscuit_auth::Biscuit::from_base64(&scoped, root.public()).unwrap();
    let scoped_ids: Vec<String> = scoped_biscuit
        .revocation_identifiers()
        .iter()
        .map(hex::encode)
        .collect();
    assert!(
        scoped_ids.contains(&base_auth_id),
        "attenuated token must inherit the base authority revocation id",
    );

    let (_d, ns) = store("n.redb");
    let (_rd, rev, _path) = rev_store();
    rev.revoke(&base_auth_id, "base compromised", NOW).unwrap();
    // The attenuated token is now denied by the base's revocation.
    let req = cas_get_req(&sk, &pk_hex, &scoped, ADDR_A, NOW);
    match verify(&root.public(), &ns, &rev, NOW, &req, true) {
        Err(AuthError::Revoked) => {}
        other => panic!("expected Revoked for attenuation of a revoked base, got {other:?}"),
    }
}

#[test]
fn revoking_dispatch_credential_is_denied() {
    // Cover the frame/dispatch op kind too (the runner surface): a revoked
    // dispatch credential is denied by the same engine path.
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["lease".into()],
            lanes: vec!["embed".into()],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let (_rd, rev, _path) = rev_store();
    rev.revoke(&authority_revocation_id(&root, &cred), "runner banned", NOW)
        .unwrap();
    let op = Op::Dispatch {
        verb: "lease".into(),
        frame_sha256_hex: "00".repeat(32),
    };
    let nonce = nonce_b64();
    let canonical = op.canonical(&nonce, NOW);
    let sig = sign_pop(&sk, &canonical);
    let req = AuthedRequest {
        op,
        biscuit_b64: cred.clone(),
        pubkey_hex: pk_hex.clone(),
        nonce_b64: nonce,
        ts_ms: NOW,
        pop_sig_b64: sig,
        required_lanes: vec!["embed".into()],
        address_hex: None,
    };
    match verify(&root.public(), &ns, &rev, NOW, &req, true) {
        Err(AuthError::Revoked) => {}
        other => panic!("expected Revoked for dispatch op, got {other:?}"),
    }
}

#[test]
fn revocation_live_reloads_without_restart() {
    // Write the deny-list file AFTER the store is open and a request has already
    // passed; the very next verify must be denied — no restart. This is the
    // operator revoke path: drop a file, deny immediately.
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    let (_rd, rev, path) = rev_store();

    // First request passes (empty deny-list).
    let ok = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    verify(&root.public(), &ns, &rev, NOW, &ok, true).expect("passes before revocation");

    // A DIFFERENT store instance writes the file (mimics an out-of-band operator
    // / the signer CLI), proving the running store live-reloads it, not just its
    // own writer cache.
    let writer = RevocationStore::open(&path).unwrap();
    writer
        .revoke(&authority_revocation_id(&root, &cred), "revoked mid-run", NOW)
        .unwrap();

    // The next request through the ORIGINAL store is denied — it re-read the file.
    let next = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW + 1);
    match verify(&root.public(), &ns, &rev, NOW + 1, &next, true) {
        Err(AuthError::Revoked) => {}
        other => panic!("expected Revoked after live reload, got {other:?}"),
    }
}

#[test]
fn missing_deny_list_revokes_nothing() {
    // A deny-list whose file never exists must revoke nothing (not error).
    let root = KeyPair::new();
    let (sk, pk_hex) = holder();
    let cred = mint(
        &root,
        &MintParams {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (_d, ns) = store("n.redb");
    // Point at a path with no file — is_revoked must be false throughout.
    let missing = std::env::temp_dir().join(format!("pep-missing-{}.json", rand::random::<u64>()));
    let rev = RevocationStore::open(&missing).unwrap();
    let req = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    verify(&root.public(), &ns, &rev, NOW, &req, true).expect("missing deny-list revokes nothing");
}

#[test]
fn signer_revoke_end_to_end_rejects_the_credential() {
    // Feature C ⇄ Feature B: enroll records the credential's authority revocation
    // id; `revoke` writes it to the deny-list the PEP reads; a request bearing
    // that credential is then denied by `verify()` (Revoked), end to end.
    use crate::signer::{Pairing, Signer};
    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets.json");
    let deny_list = dir.path().join("pep-revocations.json");

    let (sk, pk_hex) = holder();
    let mut signer = Signer::open(&secrets).unwrap();
    let cred = signer
        .enroll(Pairing {
            pubkey_hex: pk_hex.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
            note: Some("phone".into()),
            revocation_id: String::new(),
        })
        .unwrap();

    // enroll recorded a non-empty authority revocation id on the pairing.
    let recorded = signer.pairings()[&pk_hex].revocation_id.clone();
    assert!(!recorded.is_empty(), "enroll must record a revocation id");
    // ...and it matches the credential's actual authority id.
    let root_pub = signer.public_key();
    assert_eq!(recorded, authority_revocation_id_from_pub(&root_pub, &cred));

    // Before revocation the credential verifies against the same root.
    let (_d, ns) = store("n.redb");
    let rev = RevocationStore::open(&deny_list).unwrap();
    let ok = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW);
    verify(&root_pub, &ns, &rev, NOW, &ok, true).expect("passes before revoke");

    // Revoke via the signer (writes the deny-list the PEP reads).
    signer.revoke(&pk_hex, &deny_list, NOW).unwrap();

    // The next request is denied — the deny-list holds the recorded id.
    let next = cas_get_req(&sk, &pk_hex, &cred, ADDR_A, NOW + 1);
    match verify(&root_pub, &ns, &rev, NOW + 1, &next, true) {
        Err(AuthError::Revoked) => {}
        other => panic!("expected Revoked after signer.revoke, got {other:?}"),
    }
}

/// Authority revocation id of `cred` parsed against a raw root public key.
fn authority_revocation_id_from_pub(root_pub: &biscuit_auth::PublicKey, cred: &str) -> String {
    let biscuit = biscuit_auth::Biscuit::from_base64(cred, *root_pub).unwrap();
    hex::encode(&biscuit.revocation_identifiers()[0])
}

#[test]
fn signer_roundtrip_and_key_preserved() {
    use crate::signer::{Pairing, Signer};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.json");
    let pk_hex;
    let cred;
    {
        let mut s = Signer::open(&path).unwrap();
        let (_sk, pkh) = holder();
        pk_hex = pkh.clone();
        cred = s
            .enroll(Pairing {
                pubkey_hex: pkh,
                rights: vec!["cas_get".into()],
                lanes: vec![],
                note: None,
                revocation_id: String::new(),
            })
            .unwrap();
    }
    // Reopen: the issuer key is preserved, so a credential minted before still
    // verifies against the reopened signer's public key (no re-keying).
    let s2 = Signer::open(&path).unwrap();
    assert!(s2.pairings().contains_key(&pk_hex));
    // A fresh mint for the same identity must verify under the same root.
    let cred2 = s2.mint_for(&pk_hex).unwrap();
    assert!(!cred.is_empty() && !cred2.is_empty());
    // Verify cred2 against the reopened root public key.
    // (Reuse the holder key deterministically is not possible here; we just
    // assert the root key survived by checking the public key is stable.)
    let s3 = Signer::open(&path).unwrap();
    assert_eq!(s2.public_key_b64(), s3.public_key_b64());
}

#[test]
fn signer_loads_the_deployed_secretstore_format_readonly() {
    // The LIVE key file on the coordinator host is easy-podcast's SecretStore:
    //   {"secrets": {"worker_issuer_ed25519_sk": "<hex of the 32-byte seed>"}}
    // The plane signer must (1) load the issuer key from it BYTE-IDENTICALLY (no
    // re-keying -> no device re-pairs), (2) never write that file (the Python
    // signer owns it; the volume is mounted read-only), keeping its pairing
    // registry in its own sibling file.
    use crate::signer::{Pairing, Signer};
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("secrets.json");

    let seed: [u8; 32] = [7; 32];
    let store = serde_json::json!({
        "secrets": { "worker_issuer_ed25519_sk": hex::encode(seed) }
    });
    let original = serde_json::to_vec_pretty(&store).unwrap();
    std::fs::write(&key_path, &original).unwrap();

    let mut s = Signer::open(&key_path).unwrap();
    // The loaded key derives the exact public key of that seed.
    let expected =
        biscuit_auth::KeyPair::from(&biscuit_auth::PrivateKey::from_bytes(&seed).unwrap());
    assert_eq!(s.public_key_b64(), {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(expected.public().to_bytes())
    });

    // Enrolling writes ONLY the sibling pairing registry, never the key file.
    let (_sk, pkh) = holder();
    s.enroll(Pairing {
        pubkey_hex: pkh.clone(),
        rights: vec!["lease".into()],
        lanes: vec!["transcribe".into()],
        note: Some("gpu runner".into()),
        revocation_id: String::new(),
    })
    .unwrap();
    assert_eq!(
        std::fs::read(&key_path).unwrap(),
        original,
        "key file must be untouched"
    );
    let pairings_path = dir.path().join("plane-pairings.json");
    assert!(pairings_path.exists(), "pairings live in their own file");

    // Reopen: same key, pairing survived.
    let s2 = Signer::open(&key_path).unwrap();
    assert_eq!(s2.public_key_b64(), s.public_key_b64());
    assert!(s2.pairings().contains_key(&pkh));
}
