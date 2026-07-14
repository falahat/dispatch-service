//! Adversarial + happy-path integration tests for the generic HTTP PEP mode,
//! whose per-request proof is an RFC 9449 DPoP proof JWT.
//!
//! Each test stands up a real loopback echo backend and a real `HttpProxy` in
//! front of it on ephemeral ports, then drives it with a raw hyper client. The
//! echo backend reflects the method, the full path+query it received, the body,
//! and a JSON map of the headers it saw — so a test can prove BOTH that a
//! request reached the backend and that the PEP stripped the auth material.
//!
//! These are hand-authored attack tests, one per boundary the DPoP HTTP surface
//! adds. The proofs are assembled here from JOSE primitives (base64url segments +
//! an Ed25519 signature over `header.payload`) so a test can produce not just
//! valid proofs but forged, alg-confused, and tampered ones — exactly the shapes
//! a real attacker would try. `jsonwebtoken` (the PEP's verifier) and a real JOSE
//! signer agree on this format by the JWS standard; the cross-language interop is
//! proven separately in `cross_impl_py_mint.rs` (a `joserfc`-signed proof).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use biscuit_auth::KeyPair;
use dispatch_auth::cred::{mint, MintParams};
use dispatch_auth::http_proxy::{HttpProxy, RouteTableSpec};
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::quota::Quota;
use dispatch_auth::revocation::RevocationStore;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

/// The PEP's fixed clock (ms) and the equivalent whole-second `iat` a proof carries.
const NOW: i64 = 1_700_000_000_000;
const NOW_S: i64 = NOW / 1000;
/// The PEP's configured public origin — the `htu` a proof must match is rebuilt
/// from this + the request path, never from a client Host header.
const TEST_ORIGIN: &str = "https://test.example";

// ---------- DPoP proof construction (the attacker's toolkit) ----------

fn b64url(b: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// A holder identity: an Ed25519 signing key + its pubkey hex.
fn holder() -> (SigningKey, String) {
    let mut seed = [0u8; 32];
    for b in seed.iter_mut() {
        *b = rand::random::<u8>();
    }
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

/// A fresh random proof id (the DPoP `jti`, this surface's replay key).
fn jti() -> String {
    let mut b = [0u8; 16];
    for x in b.iter_mut() {
        *x = rand::random::<u8>();
    }
    b64url(b)
}

/// Assemble a compact JWS from an arbitrary header + claims, signing
/// `base64url(header).base64url(claims)` with `sk`. Arbitrary JSON so adversarial
/// tests can malform the header (alg/typ) or claims at will.
fn jws(sk: &SigningKey, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let h = b64url(serde_json::to_vec(header).unwrap());
    let p = b64url(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig = sk.sign(signing_input.as_bytes()).to_bytes();
    format!("{signing_input}.{}", b64url(sig))
}

/// The standard DPoP protected header advertising `pub_bytes` as the OKP/Ed25519 jwk.
fn dpop_header(pub_bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64url(pub_bytes) },
    })
}

/// The standard DPoP claim set binding this method / path / biscuit / body.
fn dpop_claims(
    method: &str,
    path: &str,
    biscuit: &str,
    body: &[u8],
    iat_s: i64,
    jti: &str,
) -> serde_json::Value {
    serde_json::json!({
        "htm": method,
        "htu": format!("{TEST_ORIGIN}{path}"),
        "iat": iat_s,
        "jti": jti,
        "ath": b64url(Sha256::digest(biscuit.as_bytes())),
        "content-digest": b64url(Sha256::digest(body)),
    })
}

/// A valid proof: signed by `sk`, advertising `sk`'s own public key, binding the
/// request exactly.
#[allow(clippy::too_many_arguments)]
fn proof(
    sk: &SigningKey,
    method: &str,
    path: &str,
    biscuit: &str,
    body: &[u8],
    jti: &str,
) -> String {
    jws(
        sk,
        &dpop_header(&sk.verifying_key().to_bytes()),
        &dpop_claims(method, path, biscuit, body, NOW_S, jti),
    )
}

/// The header set for a header-auth request: the Biscuit in `Authorization: DPoP`
/// and the proof JWT in `DPoP`.
fn dpop_headers(biscuit: &str, proof: &str) -> Vec<(&'static str, String)> {
    vec![
        ("authorization", format!("DPoP {biscuit}")),
        ("dpop", proof.to_string()),
    ]
}

// ---------- test harness ----------

/// The echo backend's reflected view of the request it received.
#[derive(serde::Deserialize)]
struct Echo {
    method: String,
    uri: String, // path + query, exactly as the backend saw it
    body: String,
    headers: HashMap<String, String>,
    content_length_count: usize, // raw # of Content-Length header lines the backend received
}

/// Start a loopback echo backend; returns its `http://127.0.0.1:PORT` base.
async fn start_echo() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match ln.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(echo_handle))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn echo_handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let mut headers = HashMap::new();
    for (n, v) in req.headers().iter() {
        headers.insert(n.as_str().to_string(), v.to_str().unwrap_or("").to_string());
    }
    // How many Content-Length header lines the backend actually received. A map collapses
    // duplicates, so this raw count is the only way to prove the PEP did not relay the client's
    // Content-Length alongside its own (a duplicate a strict backend parser rejects).
    let content_length_count = req.headers().get_all("content-length").iter().count();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let echo = serde_json::json!({
        "method": method,
        "uri": uri,
        "body": String::from_utf8_lossy(&body),
        "headers": headers,
        "content_length_count": content_length_count,
    });
    Ok(Response::new(Full::new(Bytes::from(
        serde_json::to_vec(&echo).unwrap(),
    ))))
}

/// A running PEP HTTP surface plus everything a test needs to talk to it.
struct Pep {
    addr: String,
    root: KeyPair,
    /// The deny-list file path, so a revocation test can write it mid-run and
    /// prove the live-reload denies the very next request.
    revocation_path: std::path::PathBuf,
    /// The serve task. Held (not detached) so Drop can stop it BEFORE `_dir` deletes
    /// the redb file — otherwise teardown races the serving task's DB handle against
    /// the file deletion (unlink-while-open is benign on Linux but a nondeterministic
    /// cross-platform hazard, a plausible source of "redb test-parallelism" flakiness).
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Pep {
    fn drop(&mut self) {
        // Runs before any field drops (incl. `_dir`): stop serving — the task is parked
        // on accept at test end, so it releases the redb DB before the file is deleted.
        self.task.abort();
    }
}

/// Build a PEP HTTP surface from a route-table TOML body pointed at `backend`,
/// with a fixed clock at `NOW` and the given quota. The `origin` is prepended so
/// each test's `ROUTES` snippet need only list routes. Returns its address.
async fn start_pep(backend: &str, routes_toml: &str, max_req: u32, max_bytes: u64) -> Pep {
    let dir = tempfile::tempdir().unwrap();
    let ns = NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();
    let revocation_path = dir.path().join("revocations.json");
    let revocations = RevocationStore::open(&revocation_path).unwrap();
    let root = KeyPair::new();
    let full = format!("origin = \"{TEST_ORIGIN}\"\nbackend = \"{backend}\"\n{routes_toml}");
    let spec: RouteTableSpec = toml::from_str(&full).unwrap();
    let cfg = spec.resolve().unwrap();
    let now: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| NOW);
    let proxy = HttpProxy::new(
        root.public(),
        ns,
        revocations,
        cfg,
        Quota::new(max_req, max_bytes),
        now,
    );
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let task = tokio::spawn(proxy.serve(ln));
    Pep {
        addr: format!("http://{addr}"),
        root,
        revocation_path,
        task,
        _dir: dir,
    }
}

impl Pep {
    fn mint(&self, pk_hex: &str, rights: &[&str]) -> String {
        mint(
            &self.root,
            &MintParams {
                pubkey_hex: pk_hex.to_string(),
                rights: rights.iter().map(|s| s.to_string()).collect(),
                lanes: vec![],
            },
        )
        .unwrap()
    }
}

/// A single response: status code + body text.
struct Resp {
    status: u16,
    body: String,
}

impl Resp {
    fn echo(&self) -> Echo {
        serde_json::from_str(&self.body).expect("echo json")
    }
}

/// Send one request to `base` and read the whole response.
async fn send(
    base: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Resp {
    let authority = base.strip_prefix("http://").unwrap();
    let stream = TcpStream::connect(authority).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("host", authority);
    for (k, v) in headers {
        builder = builder.header(*k, v);
    }
    let req = builder.body(Full::new(Bytes::from(body.to_vec()))).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// Send a request with an HTTP/1.1 CHUNKED body (no Content-Length at all),
/// written raw so we control the framing. Used to prove the body cap is enforced
/// while buffering, not by trusting a declared length.
async fn send_chunked(
    base: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Resp {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let authority = base.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(authority).await.unwrap();
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nTransfer-Encoding: chunked\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    let _ = stream.write_all(body).await;
    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
    let mut buf = Vec::new();
    let deadline = std::time::Duration::from_secs(5);
    let _ = tokio::time::timeout(deadline, async {
        let mut chunk = [0u8; 512];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Resp {
        status,
        body: text.into_owned(),
    }
}

/// A route table used by most tests: an authed POST /upsert (header), a signed
/// GET /audio (query), and a passthrough GET /app-shell.
const ROUTES: &str = r#"
[[routes]]
methods = ["POST"]
path = "/upsert"
auth = "header"
right = "sync_write"

[[routes]]
methods = ["GET"]
prefix = "/audio"
auth = "query"
right = "audio_get"

[[routes]]
methods = ["GET"]
path = "/app-shell"
auth = "passthrough"
"#;

// ---------- happy paths (one per route kind) ----------

#[tokio::test]
async fn header_auth_happy_path_forwards_and_strips_auth() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"payload", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"payload",
    )
    .await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(echo.method, "POST");
    assert_eq!(echo.uri, "/upsert");
    assert_eq!(echo.body, "payload");
    // The backend must NEVER see the client's auth material — no Authorization, no
    // DPoP proof — and the one x-dispatch-* it MAY see is the PEP-injected identity.
    for k in echo.headers.keys() {
        assert!(
            !k.starts_with("x-dispatch-") || k == "x-dispatch-identity",
            "auth header leaked to backend: {k}"
        );
    }
    assert!(
        !echo.headers.contains_key("authorization"),
        "biscuit leaked to backend"
    );
    assert!(
        !echo.headers.contains_key("dpop"),
        "proof leaked to backend"
    );
    assert_eq!(
        echo.headers.get("x-dispatch-identity").map(String::as_str),
        Some(pk.as_str()),
        "the only x-dispatch-* the backend sees is the verified identity",
    );
}

#[tokio::test]
async fn query_auth_happy_path_consumes_auth_query() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let pr = proof(&sk, "GET", "/audio", &cred, b"", &jti());
    let q = format!(
        "/audio?id=ep42&biscuit={}&dpop={}",
        urlenc(&cred),
        urlenc(&pr),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(echo.method, "GET");
    assert_eq!(echo.uri, "/audio?id=ep42");
}

#[tokio::test]
async fn passthrough_happy_path_forwards_unauthenticated() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let r = send(&pep.addr, "GET", "/app-shell", &[], b"").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(r.echo().uri, "/app-shell");
}

// ---------- verified-identity injection (x-dispatch-identity) ----------

#[tokio::test]
async fn header_auth_injects_verified_identity_for_backend() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"payload", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"payload",
    )
    .await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(
        r.echo()
            .headers
            .get("x-dispatch-identity")
            .map(String::as_str),
        Some(pk.as_str()),
        "backend must see the verified pubkey as x-dispatch-identity",
    );
}

#[tokio::test]
async fn forwarded_post_carries_a_single_content_length() {
    // Regression: the PEP's own authoritative Content-Length is the ONLY one the backend sees.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let body = b"the app payload";
    let pr = proof(&sk, "POST", "/upsert", &cred, body, &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        body,
    )
    .await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(
        echo.content_length_count, 1,
        "the backend must receive EXACTLY one Content-Length (the PEP's), never the client's too",
    );
    assert_eq!(
        echo.headers.get("content-length").map(String::as_str),
        Some(body.len().to_string().as_str()),
        "the single Content-Length must be the true buffered body length",
    );
}

#[tokio::test]
async fn client_supplied_identity_is_stripped_and_replaced() {
    // An attacker sets x-dispatch-identity itself, hoping the backend trusts it —
    // is_forwardable strips ALL client x-dispatch-* before the PEP adds the real one.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"payload", &jti());
    let mut hdrs = dpop_headers(&cred, &pr);
    hdrs.push(("x-dispatch-identity", "attacker".to_string()));
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"payload").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(
        r.echo()
            .headers
            .get("x-dispatch-identity")
            .map(String::as_str),
        Some(pk.as_str()),
        "the forged identity must be replaced with the verified pubkey",
    );
}

#[tokio::test]
async fn query_auth_injects_verified_identity_for_backend() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let pr = proof(&sk, "GET", "/audio", &cred, b"", &jti());
    let q = format!(
        "/audio?id=ep42&biscuit={}&dpop={}",
        urlenc(&cred),
        urlenc(&pr)
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(
        r.echo()
            .headers
            .get("x-dispatch-identity")
            .map(String::as_str),
        Some(pk.as_str()),
        "query-auth must also inject the verified identity",
    );
}

#[tokio::test]
async fn passthrough_injects_no_identity() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let r = send(
        &pep.addr,
        "GET",
        "/app-shell",
        &[("x-dispatch-identity", "attacker".to_string())],
        b"",
    )
    .await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert!(
        !r.echo().headers.contains_key("x-dispatch-identity"),
        "passthrough must inject no identity, and strip any client-sent one",
    );
}

// ---------- revocation (deny-list enforcement on the HTTP surface) ----------

/// The authority-block revocation id (lowercase hex) of a credential minted by
/// `root` — what an operator puts on the deny-list to revoke it.
fn authority_revocation_id(root: &KeyPair, cred: &str) -> String {
    let biscuit = biscuit_auth::Biscuit::from_base64(cred, root.public()).unwrap();
    hex::encode(&biscuit.revocation_identifiers()[0])
}

/// Write the deny-list file the PEP reads, revoking exactly these hex ids.
fn write_deny_list(path: &std::path::Path, ids: &[&str]) {
    let revoked: Vec<_> = ids
        .iter()
        .map(|id| serde_json::json!({ "id": id, "note": "test", "revoked_at": NOW }))
        .collect();
    let doc = serde_json::json!({ "revoked": revoked });
    std::fs::write(path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
}

#[tokio::test]
async fn revoked_credential_is_403_on_header_auth() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    write_deny_list(
        &pep.revocation_path,
        &[&authority_revocation_id(&pep.root, &cred)],
    );
    let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 403, "revoked credential must be 403: {}", r.body);
}

#[tokio::test]
async fn revoked_credential_is_403_on_query_auth() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    write_deny_list(
        &pep.revocation_path,
        &[&authority_revocation_id(&pep.root, &cred)],
    );
    let pr = proof(&sk, "GET", "/audio", &cred, b"", &jti());
    let q = format!("/audio?biscuit={}&dpop={}", urlenc(&cred), urlenc(&pr));
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(
        r.status, 403,
        "revoked signed-URL credential must be 403: {}",
        r.body
    );
}

#[tokio::test]
async fn non_revoked_credential_still_passes_with_a_populated_deny_list() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    write_deny_list(&pep.revocation_path, &[&"0".repeat(64)]); // someone else
    let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 200,
        "unrelated revocation must not deny: {}",
        r.body
    );
}

#[tokio::test]
async fn revocation_live_reloads_mid_run() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);

    // First request passes (empty deny-list).
    let p1 = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
    let r1 = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &p1),
        b"x",
    )
    .await;
    assert_eq!(r1.status, 200, "passes before revocation: {}", r1.body);

    // Revoke mid-run by writing the file.
    write_deny_list(
        &pep.revocation_path,
        &[&authority_revocation_id(&pep.root, &cred)],
    );

    // The next request (fresh jti, so a revocation denial, not a replay) is denied.
    let p2 = proof(&sk, "POST", "/upsert", &cred, b"y", &jti());
    let r2 = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &p2),
        b"y",
    )
    .await;
    assert_eq!(
        r2.status, 403,
        "the very next request after revocation must be 403: {}",
        r2.body
    );
}

// ---------- adversarial: authentication boundaries ----------

#[tokio::test]
async fn forged_biscuit_from_other_root_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    // Credential minted by a DIFFERENT root — signature chain won't verify.
    let evil = KeyPair::new();
    let cred = mint(
        &evil,
        &MintParams {
            pubkey_hex: pk.clone(),
            rights: vec!["sync_write".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn garbage_biscuit_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, _pk) = holder();
    // A syntactically-valid proof (ath binds "not-a-biscuit"), but the biscuit is junk.
    let pr = proof(&sk, "POST", "/upsert", "not-a-biscuit", b"x", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers("not-a-biscuit", &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn missing_auth_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    // No Authorization / DPoP headers at all on an authed route (a downgrade attempt).
    let r = send(&pep.addr, "POST", "/upsert", &[], b"x").await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn missing_proof_header_is_401() {
    // The Biscuit is present but the DPoP proof header is not — fail closed.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (_sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let hdrs = vec![("authorization", format!("DPoP {cred}"))];
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 401, "missing proof must fail closed: {}", r.body);
}

#[tokio::test]
async fn replayed_jti_is_401_on_second_use() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
    let hdrs = dpop_headers(&cred, &pr);
    let r1 = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r1.status, 200, "first should pass: {}", r1.body);
    // Exact same proof (same jti) — single-use replay must be denied.
    let r2 = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r2.status, 401, "replay must be denied: {}", r2.body);
}

#[tokio::test]
async fn stale_iat_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    // 10 min old, window is 5 min.
    let claims = dpop_claims("POST", "/upsert", &cred, b"x", NOW_S - 600, &jti());
    let pr = jws(&sk, &dpop_header(&sk.verifying_key().to_bytes()), &claims);
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 401, "stale iat must be denied: {}", r.body);
}

#[tokio::test]
async fn wrong_right_is_403() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    // Credential grants audio_get, but /upsert requires sync_write.
    let cred = pep.mint(&pk, &["audio_get"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 403, "wrong right must be forbidden: {}", r.body);
}

// ---------- adversarial: DPoP proof integrity ----------

#[tokio::test]
async fn proof_signed_by_a_non_bound_key_is_denied() {
    // FORGE: the proof advertises + is signed by the ATTACKER's key (self-consistent
    // JWS), but the Biscuit binds the VICTIM's key. The proof verifies, but the
    // authorizer's `pubkey == presented_pubkey` check fails — a valid signature over
    // a key the credential does not bind is worthless. (403: an authorization denial.)
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (_victim, victim_pk) = holder();
    let (attacker, _attacker_pk) = holder();
    let cred = pep.mint(&victim_pk, &["sync_write"]); // bound to the victim
                                                      // Signed by + advertising the attacker key.
    let pr = proof(&attacker, "POST", "/upsert", &cred, b"x", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 403,
        "a proof keyed to a non-bound key must be denied: {}",
        r.body
    );
}

#[tokio::test]
async fn proof_advertising_victim_key_but_signed_by_attacker_is_401() {
    // FORGE 2: the proof advertises the VICTIM's jwk (to satisfy the pubkey binding)
    // but is signed by the attacker (who lacks the victim's private key). The JWS
    // signature verify fails against the advertised key — 401.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (victim, victim_pk) = holder();
    let (attacker, _) = holder();
    let cred = pep.mint(&victim_pk, &["sync_write"]);
    // Header advertises the victim's key; the JWS is signed by the attacker.
    let pr = jws(
        &attacker,
        &dpop_header(&victim.verifying_key().to_bytes()),
        &dpop_claims("POST", "/upsert", &cred, b"x", NOW_S, &jti()),
    );
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "signature must verify against the advertised jwk: {}",
        r.body
    );
}

#[tokio::test]
async fn alg_none_proof_is_401() {
    // alg=none (unsigned) must be rejected: the verifier's algorithm allowlist is
    // EdDSA-only. The signature segment is empty.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "none",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64url(sk.verifying_key().to_bytes()) },
    });
    let claims = dpop_claims("POST", "/upsert", &cred, b"x", NOW_S, &jti());
    let h = b64url(serde_json::to_vec(&header).unwrap());
    let p = b64url(serde_json::to_vec(&claims).unwrap());
    let pr = format!("{h}.{p}."); // empty signature
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 401, "alg=none must be rejected: {}", r.body);
}

#[tokio::test]
async fn alg_confusion_hs256_is_401() {
    // alg=HS256 (symmetric), hoping the verifier treats the public key as an HMAC
    // secret. The EdDSA-only allowlist rejects it before any signature check.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64url(sk.verifying_key().to_bytes()) },
    });
    let claims = dpop_claims("POST", "/upsert", &cred, b"x", NOW_S, &jti());
    let h = b64url(serde_json::to_vec(&header).unwrap());
    let p = b64url(serde_json::to_vec(&claims).unwrap());
    // A plausible-looking (but irrelevant) signature segment.
    let pr = format!("{h}.{p}.{}", b64url([0u8; 32]));
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "alg=HS256 confusion must be rejected: {}",
        r.body
    );
}

#[tokio::test]
async fn alg_confusion_rs256_is_401() {
    // alg=RS256 must be rejected by the EdDSA-only allowlist BEFORE any RSA code runs.
    // This is the guard that keeps the linked-but-unused `rsa` crate unreachable
    // (RUSTSEC-2023-0071, see auth/deny.toml): jsonwebtoken's `rust_crypto` provider
    // unavoidably links `rsa`, so admitting RS256 to the allowlist would make that
    // (unfixed-upstream) advisory reachable — and would fail this test.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "RS256",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64url(sk.verifying_key().to_bytes()) },
    });
    let claims = dpop_claims("POST", "/upsert", &cred, b"x", NOW_S, &jti());
    let h = b64url(serde_json::to_vec(&header).unwrap());
    let p = b64url(serde_json::to_vec(&claims).unwrap());
    let pr = format!("{h}.{p}.{}", b64url([0u8; 32]));
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "alg=RS256 must be rejected (keeps rsa unreachable): {}",
        r.body
    );
}

#[tokio::test]
async fn wrong_typ_is_401() {
    // typ must be dpop+jwt (RFC 9449). A plain jwt typ is rejected.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let header = serde_json::json!({
        "typ": "jwt",
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64url(sk.verifying_key().to_bytes()) },
    });
    let claims = dpop_claims("POST", "/upsert", &cred, b"x", NOW_S, &jti());
    let pr = jws(&sk, &header, &claims);
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "typ != dpop+jwt must be rejected: {}",
        r.body
    );
}

#[tokio::test]
async fn token_substitution_ath_mismatch_is_401() {
    // A VALID proof for credential A, presented with a different (also valid)
    // credential B. The `ath` (bound to A) won't match sha256(B) — reject.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred_a = pep.mint(&pk, &["sync_write"]);
    let cred_b = pep.mint(&pk, &["sync_write"]); // a second, distinct credential for the same key
    assert_ne!(
        cred_a, cred_b,
        "the two mints must differ (else the test is vacuous)"
    );
    let pr = proof(&sk, "POST", "/upsert", &cred_a, b"x", &jti()); // ath binds A
                                                                   // Present the proof with credential B in the Authorization header.
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred_b, &pr),
        b"x",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "ath must bind the presented biscuit: {}",
        r.body
    );
}

// ---------- adversarial: request tampering ----------

#[tokio::test]
async fn tampered_path_breaks_htu_401() {
    // Sign for /upsert but send to a different authed path — the `htu` the PEP
    // rebuilds won't match the proof. Both paths carry the same right, so this is a
    // proof failure, not a routing/right failure.
    let two_paths = r#"
[[routes]]
methods = ["POST"]
path = "/upsert"
auth = "header"
right = "sync_write"

[[routes]]
methods = ["POST"]
path = "/upsert-evil"
auth = "header"
right = "sync_write"
"#;
    let backend = start_echo().await;
    let pep = start_pep(&backend, two_paths, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti()); // htu = .../upsert
    let r = send(
        &pep.addr,
        "POST",
        "/upsert-evil",
        &dpop_headers(&cred, &pr),
        b"x",
    )
    .await;
    assert_eq!(r.status, 401, "tampered path must fail htu: {}", r.body);
}

#[tokio::test]
async fn tampered_method_breaks_htm_401() {
    // A proof signed for GET replayed on a POST route (same path/right) — htm mismatch.
    let routes = r#"
[[routes]]
methods = ["GET", "POST"]
path = "/thing"
auth = "header"
right = "sync_write"
"#;
    let backend = start_echo().await;
    let pep = start_pep(&backend, routes, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "GET", "/thing", &cred, b"", &jti()); // htm = GET
    let r = send(&pep.addr, "POST", "/thing", &dpop_headers(&cred, &pr), b"").await;
    assert_eq!(r.status, 401, "htm swap must fail: {}", r.body);
}

#[tokio::test]
async fn tampered_body_breaks_content_digest_401() {
    // The proof binds sha256(body) via content-digest. Sign over body A, deliver
    // body B — the digest won't match. The transport does NOT protect the body.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let pr = proof(&sk, "POST", "/upsert", &cred, b"body-A", &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        b"body-B",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "tampered body must fail content-digest: {}",
        r.body
    );
}

#[tokio::test]
async fn matching_body_authenticates_200() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let body = b"{\"k\":\"v\"}";
    let pr = proof(&sk, "POST", "/upsert", &cred, body, &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        body,
    )
    .await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(r.echo().body, "{\"k\":\"v\"}");
}

#[tokio::test]
async fn tampered_query_proof_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    // A valid proof for /audio, then flip one base64url char of the signature segment.
    let mut pr = proof(&sk, "GET", "/audio", &cred, b"", &jti());
    let last = pr.pop().unwrap();
    pr.push(if last == 'A' { 'B' } else { 'A' });
    let q = format!(
        "/audio?id=ep42&biscuit={}&dpop={}",
        urlenc(&cred),
        urlenc(&pr)
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 401, "tampered query proof must fail: {}", r.body);
}

#[tokio::test]
async fn query_proof_signed_for_other_path_is_401() {
    // A signed URL for /audio must not be replayable against /audio-secret, even
    // though both are query-auth for the same right: the path is in the proof's htu.
    let routes = r#"
[[routes]]
methods = ["GET"]
path = "/audio"
auth = "query"
right = "audio_get"

[[routes]]
methods = ["GET"]
path = "/audio-secret"
auth = "query"
right = "audio_get"
"#;
    let backend = start_echo().await;
    let pep = start_pep(&backend, routes, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let pr = proof(&sk, "GET", "/audio", &cred, b"", &jti()); // htu = .../audio
    let q = format!(
        "/audio-secret?biscuit={}&dpop={}",
        urlenc(&cred),
        urlenc(&pr)
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 401, "cross-path signed URL must fail: {}", r.body);
}

// ---------- signed-URL reuse + expiry ----------

#[tokio::test]
async fn signed_url_is_reusable_within_freshness_window() {
    // A browser <audio> element reuses ONE signed URL across range requests. Query-auth
    // is freshness-only, so the SAME URL (same jti) must succeed more than once.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let pr = proof(&sk, "GET", "/audio", &cred, b"", &jti());
    let q = format!("/audio?biscuit={}&dpop={}", urlenc(&cred), urlenc(&pr));
    let r1 = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r1.status, 200, "first read: {}", r1.body);
    let r2 = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(
        r2.status, 200,
        "reused signed URL must still pass: {}",
        r2.body
    );
}

#[tokio::test]
async fn signed_url_still_expires_when_stale() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let claims = dpop_claims("GET", "/audio", &cred, b"", NOW_S - 600, &jti()); // 10 min old
    let pr = jws(&sk, &dpop_header(&sk.verifying_key().to_bytes()), &claims);
    let q = format!("/audio?biscuit={}&dpop={}", urlenc(&cred), urlenc(&pr));
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 401, "stale signed URL must expire: {}", r.body);
}

// ---------- adversarial: routing isolation ----------

#[tokio::test]
async fn passthrough_cannot_reach_an_authed_route() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let denied = send(&pep.addr, "POST", "/upsert", &[], b"x").await;
    assert_eq!(denied.status, 401);
    let ok = send(&pep.addr, "GET", "/app-shell", &[], b"").await;
    assert_eq!(ok.status, 200);
    assert_eq!(ok.echo().uri, "/app-shell");
}

#[tokio::test]
async fn unknown_path_is_404_and_never_forwarded() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let r = send(&pep.addr, "GET", "/nope", &[], b"").await;
    assert_eq!(r.status, 404, "unknown path must 404: {}", r.body);
}

#[tokio::test]
async fn wrong_method_on_known_path_is_405() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let r = send(&pep.addr, "GET", "/upsert", &[], b"").await;
    assert_eq!(r.status, 405, "wrong method must 405: {}", r.body);
}

#[tokio::test]
async fn exact_route_wins_over_prefix() {
    let backend = start_echo().await;
    let routes = r#"
[[routes]]
methods = ["GET"]
prefix = "/api"
auth = "header"
right = "api_read"

[[routes]]
methods = ["GET"]
path = "/api/health"
auth = "passthrough"
"#;
    let pep = start_pep(&backend, routes, 1000, 1 << 30).await;
    let health = send(&pep.addr, "GET", "/api/health", &[], b"").await;
    assert_eq!(
        health.status, 200,
        "exact passthrough should win: {}",
        health.body
    );
    let other = send(&pep.addr, "GET", "/api/other", &[], b"").await;
    assert_eq!(
        other.status, 401,
        "prefix route stays authed: {}",
        other.body
    );
}

#[tokio::test]
async fn approve_credential_cannot_reject_or_dispatch() {
    // Action-first paths carry a DISTINCT right each; an approve-only credential must
    // approve but be DENIED on reject and dispatch — the capability split is real.
    let backend = start_echo().await;
    let routes = r#"
[[routes]]
methods = ["POST"]
path = "/jobs"
auth = "header"
right = "dispatch"

[[routes]]
methods = ["POST"]
prefix = "/jobs/approve"
auth = "header"
right = "approve"

[[routes]]
methods = ["POST"]
prefix = "/jobs/reject"
auth = "header"
right = "reject"
"#;
    let pep = start_pep(&backend, routes, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["approve"]);

    let p1 = proof(&sk, "POST", "/jobs/approve/7", &cred, b"{}", &jti());
    let ok = send(
        &pep.addr,
        "POST",
        "/jobs/approve/7",
        &dpop_headers(&cred, &p1),
        b"{}",
    )
    .await;
    assert_eq!(ok.status, 200, "approve right may approve: {}", ok.body);

    let p2 = proof(&sk, "POST", "/jobs/reject/7", &cred, b"{}", &jti());
    let no_reject = send(
        &pep.addr,
        "POST",
        "/jobs/reject/7",
        &dpop_headers(&cred, &p2),
        b"{}",
    )
    .await;
    assert_eq!(
        no_reject.status, 403,
        "approve right must NOT reject: {}",
        no_reject.body
    );

    let p3 = proof(&sk, "POST", "/jobs", &cred, b"{}", &jti());
    let no_dispatch = send(&pep.addr, "POST", "/jobs", &dpop_headers(&cred, &p3), b"{}").await;
    assert_eq!(
        no_dispatch.status, 403,
        "approve right must NOT dispatch: {}",
        no_dispatch.body
    );
}

// ---------- adversarial: size + rate ----------

/// An 8-byte-capped route table used by the oversize tests.
const CAP8_ROUTES: &str = r#"
max_body_bytes = 8

[[routes]]
methods = ["POST"]
path = "/upsert"
auth = "header"
right = "sync_write"
"#;

#[tokio::test]
async fn oversize_body_is_413_with_truthful_length() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, CAP8_ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let big = vec![b'z'; 20];
    let pr = proof(&sk, "POST", "/upsert", &cred, &big, &jti());
    let r = send(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        &big,
    )
    .await;
    assert_eq!(r.status, 413, "oversize must be 413: {}", r.body);
}

#[tokio::test]
async fn oversize_body_is_413_with_no_content_length() {
    // The cap must NOT rely on Content-Length: a chunked oversize body is caught
    // WHILE buffering, before auth even runs.
    let backend = start_echo().await;
    let pep = start_pep(&backend, CAP8_ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let big = vec![b'z'; 20];
    let pr = proof(&sk, "POST", "/upsert", &cred, &big, &jti());
    let r = send_chunked(
        &pep.addr,
        "POST",
        "/upsert",
        &dpop_headers(&cred, &pr),
        &big,
    )
    .await;
    assert_eq!(
        r.status, 413,
        "chunked oversize must be 413 (no CL to trust): {}",
        r.body
    );
}

#[tokio::test]
async fn request_quota_exhaustion_is_429() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 2, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let mut last = 0u16;
    for _ in 0..3 {
        let pr = proof(&sk, "POST", "/upsert", &cred, b"x", &jti());
        last = send(
            &pep.addr,
            "POST",
            "/upsert",
            &dpop_headers(&cred, &pr),
            b"x",
        )
        .await
        .status;
    }
    assert_eq!(last, 429, "quota should be exhausted by the 3rd request");
}

// ---------- route-table validation (boot-time) ----------

/// Prepend the required `origin` to a routes-only TOML for the validation tests.
fn with_origin(routes: &str) -> String {
    format!("origin = \"{TEST_ORIGIN}\"\nbackend = \"http://127.0.0.1:1\"\n{routes}")
}

#[test]
fn route_table_rejects_missing_origin() {
    // origin is REQUIRED — a DPoP htu is unverifiable without it, so a table that
    // omits it must not even parse.
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["GET"]
path = "/x"
auth = "passthrough"
"#;
    assert!(
        toml::from_str::<RouteTableSpec>(toml).is_err(),
        "a route table without origin must be rejected",
    );
}

#[test]
fn route_table_rejects_origin_without_scheme() {
    let toml = r#"
origin = "easypod.example"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["GET"]
path = "/x"
auth = "passthrough"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
    assert!(
        spec.resolve().is_err(),
        "a bare-host origin (no scheme) must be rejected"
    );
}

#[test]
fn route_table_rejects_ambiguous_matcher() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["GET"]
path = "/x"
prefix = "/x"
auth = "passthrough"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(spec.resolve().is_err(), "path+prefix must be rejected");
}

#[test]
fn route_table_rejects_root_prefix() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["GET"]
prefix = "/"
auth = "passthrough"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(spec.resolve().is_err(), "prefix \"/\" must be rejected");
}

#[test]
fn route_table_rejects_authed_route_without_right() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["POST"]
path = "/x"
auth = "header"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(spec.resolve().is_err(), "header auth needs a right");
}

#[test]
fn route_table_rejects_passthrough_with_right() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["GET"]
path = "/x"
auth = "passthrough"
right = "sneaky"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(spec.resolve().is_err(), "passthrough must take no right");
}

#[test]
fn route_table_rejects_unknown_auth() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["GET"]
path = "/x"
auth = "magic"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(
        spec.resolve().is_err(),
        "unknown auth mode must be rejected"
    );
}

#[test]
fn route_table_rejects_query_auth_on_mutating_method() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["POST"]
path = "/x"
auth = "query"
right = "audio_get"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(
        spec.resolve().is_err(),
        "query auth on POST must be rejected"
    );
}

#[test]
fn route_table_allows_query_auth_on_get_and_head() {
    let toml = with_origin(
        r#"
[[routes]]
methods = ["GET", "HEAD"]
path = "/audio"
auth = "query"
right = "audio_get"
"#,
    );
    let spec: RouteTableSpec = toml::from_str(&toml).unwrap();
    assert!(spec.resolve().is_ok(), "GET/HEAD query auth is allowed");
}

// ---------- helpers ----------

/// Minimal percent-encoding for query values (base64 uses +, /, =).
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
