//! Adversarial + happy-path integration tests for the dispatcher runner-surface proxy.
//!
//! `FrameProxy` terminates a runner's length-prefixed framed connection, verifies Biscuit
//! plus the bespoke `dispatch/v0` PoP on EVERY frame, and forwards the clean inner frame to
//! the dispatcher over loopback. The wire is a 4-byte big-endian length prefix then a JSON
//! auth frame (`b` biscuit, `k` pubkey, `n` nonce, `t` ts, `s` pop, `m` base64 inner frame);
//! the PoP signs `dispatch/v0 <verb> <sha256hex(inner)> <nonce> <ts>`. A denial is a framed
//! `error` reply carrying a `code` (`unauthenticated`, `forbidden`, or `invalid`); an accept
//! pipes the dispatcher's reply straight back.
//!
//! Each test stands up a real loopback dispatcher stub and a real `FrameProxy` on ephemeral
//! ports and drives it with a raw frame client. Hand-authored attack tests, one per boundary
//! the frame surface adds over the shared `verify()` engine: forged and garbage biscuits,
//! malformed outer and inner frames, replay, stale ts, a verb the credential lacks, a lane it
//! lacks, revocation, the hello-identity binding, a tampered inner frame, and frame-length
//! bounds.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::KeyPair;
use dispatch_auth::frame_proxy::FrameProxy;
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::revocation::RevocationStore;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NOW: i64 = 1_700_000_000_000;

// ---------- framed transport helpers ----------

async fn read_frame(s: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match s.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame(s: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    s.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    s.write_all(payload).await?;
    s.flush().await
}

// ---------- PoP signing (bespoke dispatch/v0 canonical) ----------

fn holder() -> (SigningKey, String) {
    let mut seed = [0u8; 32];
    for b in seed.iter_mut() {
        *b = rand::random::<u8>();
    }
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

fn nonce_b64() -> String {
    let mut b = [0u8; 32];
    for x in b.iter_mut() {
        *x = rand::random::<u8>();
    }
    STANDARD.encode(b)
}

/// Sign `dispatch/v0 <verb> <sha256hex(inner)> <nonce> <ts>`.
fn sign_dispatch(sk: &SigningKey, verb: &str, inner: &[u8], nonce: &str, ts: i64) -> String {
    let frame_hash = hex::encode(Sha256::digest(inner));
    let canonical = format!("dispatch/v0 {verb} {frame_hash} {nonce} {ts}");
    STANDARD.encode(sk.sign(canonical.as_bytes()).to_bytes())
}

// ---------- inner + auth frame builders ----------

fn inner_hello(id: &str, runner_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": "0.1", "type": "hello", "id": id, "body": { "runner": { "id": runner_id } }
    }))
    .unwrap()
}

fn inner_lease(id: &str, lanes: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": "0.1", "type": "lease", "id": id, "body": { "lanes": lanes }
    }))
    .unwrap()
}

/// A minimal inner frame for a generic verb (heartbeat/complete/…): type + id + empty body.
fn inner_verb(verb: &str, id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "v": "0.1", "type": verb, "id": id, "body": {} }))
        .unwrap()
}

/// Assemble the outer auth frame JSON for `inner`, signed as `verb`.
#[allow(clippy::too_many_arguments)]
fn auth_frame(biscuit: &str, pk: &str, nonce: &str, ts: i64, pop: &str, inner: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "b": biscuit, "k": pk, "n": nonce, "t": ts, "s": pop, "m": STANDARD.encode(inner)
    }))
    .unwrap()
}

/// A fully-signed auth frame for `verb`/`inner` under `sk`+`cred`, at `NOW` with a fresh nonce.
fn signed_frame(sk: &SigningKey, pk: &str, cred: &str, verb: &str, inner: &[u8]) -> Vec<u8> {
    let nonce = nonce_b64();
    let pop = sign_dispatch(sk, verb, inner, &nonce, NOW);
    auth_frame(cred, pk, &nonce, NOW, &pop, inner)
}

// ---------- dispatcher stub + PEP harness ----------

/// A loopback dispatcher stub: per connection, echoes a `reply` frame for every inner frame it
/// receives (the clean frame the PEP forwards on an ACCEPT). Returns its `host:port`.
async fn start_dispatcher() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match ln.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                while let Ok(Some(inner)) = read_frame(&mut stream).await {
                    let v: serde_json::Value = serde_json::from_slice(&inner).unwrap_or_default();
                    let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("0");
                    let reply = serde_json::to_vec(&serde_json::json!({
                        "v": "0.1", "type": "reply", "id": id, "body": { "ok": true }
                    }))
                    .unwrap();
                    if write_frame(&mut stream, &reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr.to_string()
}

struct Pep {
    addr: String,
    root: KeyPair,
    revocation_path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Pep {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_pep(dispatcher_addr: &str) -> Pep {
    let dir = tempfile::tempdir().unwrap();
    let ns = NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();
    let revocation_path = dir.path().join("revocations.json");
    let revocations = RevocationStore::open(&revocation_path).unwrap();
    let root = KeyPair::new();
    let now: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| NOW);
    let proxy = FrameProxy::new(
        root.public(),
        ns,
        revocations,
        dispatcher_addr.to_string(),
        now,
    );
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let task = tokio::spawn(proxy.serve(ln));
    Pep {
        addr: addr.to_string(),
        root,
        revocation_path,
        task,
        _dir: dir,
    }
}

impl Pep {
    fn mint(&self, pk_hex: &str, rights: &[&str], lanes: &[&str]) -> String {
        dispatch_auth::mint(
            &self.root,
            &dispatch_auth::MintParams {
                pubkey_hex: pk_hex.to_string(),
                rights: rights.iter().map(|s| s.to_string()).collect(),
                lanes: lanes.iter().map(|s| s.to_string()).collect(),
            },
        )
        .unwrap()
    }

    fn revoke(&self, cred: &str) {
        let id = hex::encode(
            &biscuit_auth::Biscuit::from_base64(cred, self.root.public())
                .unwrap()
                .revocation_identifiers()[0],
        );
        let doc = serde_json::json!({ "revoked": [{ "id": id, "note": "t", "revoked_at": NOW }] });
        std::fs::write(&self.revocation_path, serde_json::to_vec(&doc).unwrap()).unwrap();
    }
}

/// Open ONE connection, send `frame`, and read a single reply frame (None on a connection close).
async fn exchange(pep_addr: &str, frame: &[u8]) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(pep_addr).await.unwrap();
    write_frame(&mut s, frame).await.unwrap();
    read_frame(&mut s).await.unwrap()
}

/// The `(type, code)` of a reply frame — `("error", <code>)` on a denial, `("reply", "")` on accept.
fn reply_kind(frame: &[u8]) -> (String, String) {
    let v: serde_json::Value = serde_json::from_slice(frame).expect("reply is json");
    let typ = v
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let code = v
        .get("body")
        .and_then(|b| b.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    (typ, code)
}

fn assert_denied(frame: &Option<Vec<u8>>, want_code: &str) {
    let bytes = frame.as_ref().expect("a denial is still a framed reply");
    let (typ, code) = reply_kind(bytes);
    assert_eq!(typ, "error", "expected an error frame, got {typ}");
    assert_eq!(code, want_code, "wrong denial code");
}

// ---------- happy path ----------

#[tokio::test]
async fn hello_happy_path_forwards_and_pipes_reply() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    let inner = inner_hello("f1", &pk); // hello's declared runner id == the verified pubkey
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "hello", &inner)).await;
    let (typ, _) = reply_kind(reply.as_ref().expect("a reply"));
    assert_eq!(
        typ, "reply",
        "a valid hello must be forwarded and its reply piped back"
    );
}

#[tokio::test]
async fn lease_with_granted_lane_is_forwarded() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["lease"], &["gpu"]); // grants the lease right AND the gpu lane
    let inner = inner_lease("f1", &["gpu"]);
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "lease", &inner)).await;
    let (typ, _) = reply_kind(reply.as_ref().expect("a reply"));
    assert_eq!(typ, "reply", "a lease for a granted lane must be forwarded");
}

// ---------- adversarial: authentication ----------

#[tokio::test]
async fn forged_biscuit_from_other_root_is_unauthenticated() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let evil = KeyPair::new();
    let cred = dispatch_auth::mint(
        &evil,
        &dispatch_auth::MintParams {
            pubkey_hex: pk.clone(),
            rights: vec!["hello".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let inner = inner_hello("f1", &pk);
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "hello", &inner)).await;
    assert_denied(&reply, "unauthenticated");
}

#[tokio::test]
async fn garbage_biscuit_is_unauthenticated() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let inner = inner_hello("f1", &pk);
    let reply = exchange(
        &pep.addr,
        &signed_frame(&sk, &pk, "not-a-biscuit", "hello", &inner),
    )
    .await;
    assert_denied(&reply, "unauthenticated");
}

#[tokio::test]
async fn malformed_auth_frame_is_invalid() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let reply = exchange(&pep.addr, b"this is not json").await;
    assert_denied(&reply, "invalid");
}

#[tokio::test]
async fn bad_inner_base64_is_invalid() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (_sk, pk) = holder();
    // A well-formed auth frame whose `m` is not valid base64.
    let frame = serde_json::to_vec(&serde_json::json!({
        "b": "x", "k": pk, "n": "n", "t": NOW, "s": "s", "m": "!!!not-base64!!!"
    }))
    .unwrap();
    let reply = exchange(&pep.addr, &frame).await;
    assert_denied(&reply, "invalid");
}

#[tokio::test]
async fn malformed_inner_frame_is_invalid() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (_sk, pk) = holder();
    // Valid base64, but the inner bytes are not a well-formed frame (no type/id).
    let frame = serde_json::to_vec(&serde_json::json!({
        "b": "x", "k": pk, "n": "n", "t": NOW, "s": "s", "m": STANDARD.encode(b"{}")
    }))
    .unwrap();
    let reply = exchange(&pep.addr, &frame).await;
    assert_denied(&reply, "invalid");
}

#[tokio::test]
async fn replayed_nonce_is_denied_on_second_use() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    let inner = inner_hello("f1", &pk);
    let frame = signed_frame(&sk, &pk, &cred, "hello", &inner);
    let r1 = exchange(&pep.addr, &frame).await;
    assert_eq!(reply_kind(r1.as_ref().unwrap()).0, "reply", "first passes");
    // Exact same frame (same nonce) — single-use replay must be denied.
    let r2 = exchange(&pep.addr, &frame).await;
    assert_denied(&r2, "unauthenticated");
}

#[tokio::test]
async fn stale_ts_is_unauthenticated() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    let inner = inner_hello("f1", &pk);
    let stale = NOW - 10 * 60 * 1000;
    let nonce = nonce_b64();
    let pop = sign_dispatch(&sk, "hello", &inner, &nonce, stale);
    let frame = auth_frame(&cred, &pk, &nonce, stale, &pop, &inner);
    let reply = exchange(&pep.addr, &frame).await;
    assert_denied(&reply, "unauthenticated");
}

#[tokio::test]
async fn tampered_inner_frame_breaks_pop() {
    // Sign the PoP over inner A, but ship inner B in `m` — the frame hash the PEP recomputes
    // (over the DELIVERED inner) won't match what was signed, so the PoP fails.
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    let signed_inner = inner_hello("f1", &pk);
    let delivered_inner = inner_hello("f2", &pk); // different bytes
    let nonce = nonce_b64();
    let pop = sign_dispatch(&sk, "hello", &signed_inner, &nonce, NOW); // signs A
    let frame = auth_frame(&cred, &pk, &nonce, NOW, &pop, &delivered_inner); // ships B
    let reply = exchange(&pep.addr, &frame).await;
    assert_denied(&reply, "unauthenticated");
}

// ---------- adversarial: capability + lanes + identity + revocation ----------

#[tokio::test]
async fn verb_the_credential_lacks_is_forbidden() {
    // A hello-only credential can't lease (each verb IS its own required right).
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    let inner = inner_verb("lease", "f1");
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "lease", &inner)).await;
    assert_denied(&reply, "forbidden");
}

#[tokio::test]
async fn lease_for_an_ungranted_lane_is_forbidden() {
    // The credential grants the `lease` right but NOT the `gpu` lane — a lease scoped to gpu
    // must be denied (the lane check is separate from the right).
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["lease"], &["cpu"]); // lease + cpu lane, but NOT gpu
    let inner = inner_lease("f1", &["gpu"]);
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "lease", &inner)).await;
    assert_denied(&reply, "forbidden");
}

#[tokio::test]
async fn revoked_credential_is_forbidden() {
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    pep.revoke(&cred);
    let inner = inner_hello("f1", &pk);
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "hello", &inner)).await;
    assert_denied(&reply, "forbidden");
}

#[tokio::test]
async fn hello_declaring_another_identity_is_forbidden() {
    // The hello frame's declared runner id must equal the credential-verified pubkey, so a holder
    // can't register under someone else's fleet identity even with a valid credential.
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["hello"], &[]);
    let inner = inner_hello("f1", &"a".repeat(64)); // a DIFFERENT runner id
    let reply = exchange(&pep.addr, &signed_frame(&sk, &pk, &cred, "hello", &inner)).await;
    assert_denied(&reply, "forbidden");
}

// ---------- adversarial: frame-length bounds ----------

#[tokio::test]
async fn zero_length_frame_closes_the_connection() {
    // A declared length of 0 is a protocol violation the PEP refuses at the transport — the
    // connection is dropped, not answered with a frame.
    let dispatcher = start_dispatcher().await;
    let pep = start_pep(&dispatcher).await;
    let mut s = TcpStream::connect(&pep.addr).await.unwrap();
    s.write_all(&0u32.to_be_bytes()).await.unwrap();
    s.flush().await.unwrap();
    // No valid reply frame comes back — the PEP closed the connection.
    assert!(
        read_frame(&mut s).await.unwrap().is_none(),
        "zero-length frame must drop the conn"
    );
}
