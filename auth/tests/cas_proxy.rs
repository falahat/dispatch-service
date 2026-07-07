//! Adversarial + happy-path integration tests for the CAS enforcement proxy.
//!
//! `CasProxy` fronts a blob store (bazel-remote / a stub) and enforces Biscuit + the
//! bespoke `cas/v0` PoP on every blob request before streaming it through. Unlike the
//! browser-facing HTTP surface (DPoP), the runner surfaces keep the canonical-string
//! PoP: `cas/v0 <METHOD> <path> <nonce> <ts>` — the blob address in the path IS the
//! content commitment, so the signature binds method + path + nonce + ts (no body hash).
//!
//! Each test stands up a real loopback blob-store stub and a real `CasProxy` on ephemeral
//! ports, then drives it with a raw hyper client. These are hand-authored attack tests,
//! one per boundary the CAS surface adds on top of the shared `verify()` engine (which
//! `src/tests.rs` covers at the unit level): the `x-dispatch-*` extraction, the blob-path
//! parser, the cas_get/cas_put/cas_deny right mapping, the Content-Length-required + size
//! cap + quota, and that no client auth material leaks to the backend.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::KeyPair;
use dispatch_auth::cas_proxy::{BackendStyle, CasConfig, CasProxy};
use dispatch_auth::cred::{mint, MintParams};
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::quota::Quota;
use dispatch_auth::revocation::RevocationStore;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

const NOW: i64 = 1_700_000_000_000;

/// A valid 64-char lowercase-hex blob address (the CAS surface's only path shape).
const ADDR: &str = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd";
/// A DIFFERENT valid address, for the tampered-path test.
const ADDR2: &str = "def456def456def456def456def456def456def456def456def456def456def4";

fn blob_path(addr: &str) -> String {
    format!("/blobs/sha256/{addr}")
}

// ---------- PoP signing (bespoke cas/v0 canonical) ----------

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

/// Sign the CAS canonical `cas/v0 <METHOD> <path> <nonce> <ts>` (no body hash — the address
/// in the path is the content commitment).
fn sign_cas(sk: &SigningKey, method: &str, path: &str, nonce: &str, ts: i64) -> String {
    let canonical = format!("cas/v0 {method} {path} {nonce} {ts}");
    STANDARD.encode(sk.sign(canonical.as_bytes()).to_bytes())
}

/// The five `x-dispatch-*` auth headers for a CAS request.
fn auth_headers(
    biscuit: &str,
    pubkey: &str,
    nonce: &str,
    ts: i64,
    pop: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("x-dispatch-biscuit", biscuit.to_string()),
        ("x-dispatch-pubkey", pubkey.to_string()),
        ("x-dispatch-nonce", nonce.to_string()),
        ("x-dispatch-ts", ts.to_string()),
        ("x-dispatch-pop", pop.to_string()),
    ]
}

// ---------- blob-store stub backend ----------

#[derive(serde::Deserialize)]
struct Echo {
    method: String,
    uri: String,
    body: String,
    headers: HashMap<String, String>,
}

/// A loopback blob-store stub: reflects the method, path, body, and the headers it saw (so a
/// test can prove the request reached it AND that the PEP stripped the client auth material).
async fn start_store() -> String {
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
                    .serve_connection(io, service_fn(store_handle))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn store_handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let mut headers = HashMap::new();
    for (n, v) in req.headers().iter() {
        headers.insert(n.as_str().to_string(), v.to_str().unwrap_or("").to_string());
    }
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let echo = serde_json::json!({
        "method": method,
        "uri": uri,
        "body": String::from_utf8_lossy(&body),
        "headers": headers,
    });
    Ok(Response::new(Full::new(Bytes::from(
        serde_json::to_vec(&echo).unwrap(),
    ))))
}

// ---------- PEP harness ----------

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

async fn start_pep(backend: &str, max_blob_bytes: u64, max_req: u32, max_bytes: u64) -> Pep {
    let dir = tempfile::tempdir().unwrap();
    let ns = NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();
    let revocation_path = dir.path().join("revocations.json");
    let revocations = RevocationStore::open(&revocation_path).unwrap();
    let root = KeyPair::new();
    let now: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| NOW);
    let proxy = CasProxy::new(
        root.public(),
        ns,
        revocations,
        CasConfig {
            backend: backend.to_string(),
            max_blob_bytes,
            style: BackendStyle::Passthrough,
        },
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

struct Resp {
    status: u16,
    body: String,
}

impl Resp {
    fn echo(&self) -> Echo {
        serde_json::from_str(&self.body).expect("echo json")
    }
}

/// Send one request, optionally with an explicit Content-Length override (for the CAS
/// `content_length_required` + cap tests, which read the client's declared length).
async fn send(
    base: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
    content_length: Option<&str>,
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
        .uri(path)
        .header("host", authority);
    for (k, v) in headers {
        builder = builder.header(*k, v);
    }
    if let Some(cl) = content_length {
        builder = builder.header("content-length", cl);
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

/// A signed GET for `addr` with a fresh nonce at `NOW`.
fn signed_get(
    sk: &SigningKey,
    pk: &str,
    cred: &str,
    addr: &str,
) -> (String, Vec<(&'static str, String)>) {
    let path = blob_path(addr);
    let nonce = nonce_b64();
    let pop = sign_cas(sk, "GET", &path, &nonce, NOW);
    (path, auth_headers(cred, pk, &nonce, NOW, &pop))
}

// ---------- happy paths ----------

#[tokio::test]
async fn cas_get_happy_path_forwards_and_strips_auth() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let (path, hdrs) = signed_get(&sk, &pk, &cred, ADDR);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(echo.method, "GET");
    assert!(echo.uri.ends_with(&blob_path(ADDR)), "uri: {}", echo.uri);
    // The blob store must NEVER see the client's auth material.
    for k in echo.headers.keys() {
        assert!(
            !k.starts_with("x-dispatch-"),
            "auth header leaked to backend: {k}"
        );
    }
}

#[tokio::test]
async fn cas_put_happy_path_forwards_body() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_put"]);
    let path = blob_path(ADDR);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "PUT", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "PUT", &path, &hdrs, b"blob-bytes", Some("10")).await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(r.echo().body, "blob-bytes");
}

#[tokio::test]
async fn cas_head_happy_path() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]); // HEAD maps to cas_get
    let path = blob_path(ADDR);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "HEAD", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "HEAD", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 200, "body: {}", r.body);
}

// ---------- adversarial: authentication ----------

#[tokio::test]
async fn forged_biscuit_from_other_root_is_401() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let evil = KeyPair::new();
    let cred = mint(
        &evil,
        &MintParams {
            pubkey_hex: pk.clone(),
            rights: vec!["cas_get".into()],
            lanes: vec![],
        },
    )
    .unwrap();
    let (path, hdrs) = signed_get(&sk, &pk, &cred, ADDR);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn garbage_biscuit_is_401() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let (path, hdrs) = signed_get(&sk, &pk, "not-a-biscuit", ADDR);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn missing_auth_headers_is_401() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let r = send(&pep.addr, "GET", &blob_path(ADDR), &[], b"", None).await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn replayed_nonce_is_401_on_second_use() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let (path, hdrs) = signed_get(&sk, &pk, &cred, ADDR);
    let r1 = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r1.status, 200, "first: {}", r1.body);
    let r2 = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r2.status, 401, "replay must be denied: {}", r2.body);
}

#[tokio::test]
async fn stale_ts_is_401() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let path = blob_path(ADDR);
    let stale = NOW - 10 * 60 * 1000;
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "GET", &path, &nonce, stale);
    let hdrs = auth_headers(&cred, &pk, &nonce, stale, &pop);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 401, "stale ts must be denied: {}", r.body);
}

#[tokio::test]
async fn tampered_path_breaks_pop_401() {
    // Sign for ADDR but request ADDR2 — the rebuilt canonical won't match, so PoP fails.
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "GET", &blob_path(ADDR), &nonce, NOW); // signs ADDR
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "GET", &blob_path(ADDR2), &hdrs, b"", None).await; // requests ADDR2
    assert_eq!(r.status, 401, "tampered path must fail PoP: {}", r.body);
}

#[tokio::test]
async fn tampered_method_breaks_pop_401() {
    // Sign for GET but send PUT (same path) — the method is in the canonical, so PoP fails.
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get", "cas_put"]);
    let path = blob_path(ADDR);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "GET", &path, &nonce, NOW); // signs GET
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "PUT", &path, &hdrs, b"x", Some("1")).await; // sends PUT
    assert_eq!(r.status, 401, "method swap must fail PoP: {}", r.body);
}

// ---------- adversarial: capability (cas_get vs cas_put) ----------

#[tokio::test]
async fn get_right_cannot_put_403() {
    // A cas_get-only credential must be denied a PUT (which requires cas_put).
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let path = blob_path(ADDR);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "PUT", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "PUT", &path, &hdrs, b"x", Some("1")).await;
    assert_eq!(r.status, 403, "cas_get must not PUT: {}", r.body);
}

#[tokio::test]
async fn put_right_cannot_get_403() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_put"]); // put only
    let (path, hdrs) = signed_get(&sk, &pk, &cred, ADDR);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 403, "cas_put must not GET: {}", r.body);
}

#[tokio::test]
async fn revoked_credential_is_403() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let id = hex::encode(
        &biscuit_auth::Biscuit::from_base64(&cred, pep.root.public())
            .unwrap()
            .revocation_identifiers()[0],
    );
    let doc = serde_json::json!({ "revoked": [{ "id": id, "note": "t", "revoked_at": NOW }] });
    std::fs::write(&pep.revocation_path, serde_json::to_vec(&doc).unwrap()).unwrap();
    let (path, hdrs) = signed_get(&sk, &pk, &cred, ADDR);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 403, "revoked credential must be 403: {}", r.body);
}

// ---------- adversarial: path shape + method ----------

#[tokio::test]
async fn non_blob_path_is_404() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    // A path that is not /blobs/sha256/<64 lowercase hex> is a 404 (no LIST/DELETE surface).
    for bad in [
        "/blobs/sha256/tooshort",
        "/blobs/sha256/ABC123",
        "/other",
        "/blobs/sha256/",
    ] {
        let nonce = nonce_b64();
        let pop = sign_cas(&sk, "GET", bad, &nonce, NOW);
        let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
        let r = send(&pep.addr, "GET", bad, &hdrs, b"", None).await;
        assert_eq!(r.status, 404, "{bad} must 404: {}", r.body);
    }
}

#[tokio::test]
async fn uppercase_hex_address_is_404() {
    // The address must be lowercase hex — an uppercase one is not a valid CAS path.
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let upper = ADDR.to_uppercase();
    let path = blob_path(&upper);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "GET", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "GET", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 404, "uppercase hex must 404: {}", r.body);
}

#[tokio::test]
async fn disallowed_method_is_405() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let path = blob_path(ADDR);
    // DELETE is a valid blob path but not a permitted method (only GET/HEAD/PUT).
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "DELETE", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "DELETE", &path, &hdrs, b"", None).await;
    assert_eq!(r.status, 405, "DELETE must 405: {}", r.body);
}

// ---------- adversarial: size + rate ----------

#[tokio::test]
async fn put_without_content_length_is_400() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 1000, 1 << 40).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_put"]);
    let path = blob_path(ADDR);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "PUT", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    // hyper adds a Content-Length for a sized Full body, so force a chunked (length-less) PUT.
    let r = send_chunked(&pep.addr, "PUT", &path, &hdrs, b"x").await;
    assert_eq!(
        r.status, 400,
        "PUT without Content-Length must 400: {}",
        r.body
    );
}

#[tokio::test]
async fn put_oversize_is_413() {
    let store = start_store().await;
    let pep = start_pep(&store, 8, 1000, 1 << 40).await; // 8-byte blob cap
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_put"]);
    let path = blob_path(ADDR);
    let nonce = nonce_b64();
    let pop = sign_cas(&sk, "PUT", &path, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "PUT", &path, &hdrs, &[b'z'; 20], Some("20")).await;
    assert_eq!(r.status, 413, "oversize PUT must 413: {}", r.body);
}

#[tokio::test]
async fn request_quota_exhaustion_is_429() {
    let store = start_store().await;
    let pep = start_pep(&store, 1 << 30, 2, 1 << 40).await; // 2 req/min
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["cas_get"]);
    let mut last = 0u16;
    for _ in 0..3 {
        let (path, hdrs) = signed_get(&sk, &pk, &cred, ADDR);
        last = send(&pep.addr, "GET", &path, &hdrs, b"", None).await.status;
    }
    assert_eq!(last, 429, "quota should be exhausted by the 3rd request");
}

// ---------- helper: chunked (length-less) PUT ----------

/// Send a PUT with an HTTP/1.1 CHUNKED body (no Content-Length), so the CAS
/// `content_length_required` path is exercised.
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
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
