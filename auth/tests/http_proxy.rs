//! Adversarial + happy-path integration tests for the generic HTTP PEP mode.
//!
//! Each test stands up a real loopback echo backend and a real `HttpProxy` in
//! front of it on ephemeral ports, then drives it with a raw hyper client. The
//! echo backend reflects the method, the full path+query it received, the body,
//! and a JSON map of the headers it saw — so a test can prove BOTH that a
//! request reached the backend and that the PEP stripped the auth material.
//!
//! These are hand-authored attack tests, one per boundary the HTTP surface adds:
//! forged/invalid biscuit, replayed nonce, stale ts, wrong right, tampered
//! path/body, tampered query-auth, a passthrough route that must never reach an
//! authed backend route, oversize (caught during buffering), and quota. Plus the
//! two hardenings: the PoP binds the body (tamper the body → 401), and a
//! signed-URL query read is reusable within its freshness window but expires.
//! The core engine's own boundaries (PoP forgery, biscuit signature,
//! pubkey-binding) are already covered in the crate's unit `tests.rs`; here we
//! prove the HTTP wiring feeds `verify()` faithfully and fails closed end to end.

use base64::{engine::general_purpose::STANDARD, Engine as _};
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

const NOW: i64 = 1_700_000_000_000;

// ---------- test harness ----------

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

fn nonce_b64() -> String {
    let mut b = [0u8; 32];
    for x in b.iter_mut() {
        *x = rand::random::<u8>();
    }
    STANDARD.encode(b)
}

/// Sign the HTTP canonical string, which binds the body:
/// `http/v0 <METHOD> <path> <sha256hex(body)> <nonce> <ts>`.
fn sign_http(
    sk: &SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &str,
    ts: i64,
) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    let canonical = format!("http/v0 {method} {path} {body_hash} {nonce} {ts}");
    STANDARD.encode(sk.sign(canonical.as_bytes()).to_bytes())
}

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
    _dir: tempfile::TempDir,
}

/// Build a PEP HTTP surface from a route-table TOML body pointed at `backend`,
/// with a fixed clock at `NOW` and the given quota. Returns its address.
async fn start_pep(backend: &str, routes_toml: &str, max_req: u32, max_bytes: u64) -> Pep {
    let dir = tempfile::tempdir().unwrap();
    let ns = NonceStore::open(dir.path().join("n.redb"), dispatch_auth::DEFAULT_WINDOW_MS).unwrap();
    let revocation_path = dir.path().join("revocations.json");
    let revocations = RevocationStore::open(&revocation_path).unwrap();
    let root = KeyPair::new();
    let full = format!("backend = \"{backend}\"\n{routes_toml}");
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
    tokio::spawn(proxy.serve(ln));
    Pep {
        addr: format!("http://{addr}"),
        root,
        revocation_path,
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
/// while buffering, not by trusting a declared length. Reads the status line
/// back; the PEP is expected to reject the oversize body before the chunks end.
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
    // One chunk carrying the whole (oversize) body, then the terminating chunk.
    // The PEP is expected to reject mid-stream; the terminating chunk may never
    // be consumed, so we do NOT block waiting for the connection to close —
    // we read only the response head, under a timeout.
    stream
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    let _ = stream.write_all(body).await;
    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
    // Read until the end of the response headers (\r\n\r\n) or a short timeout.
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

/// The five auth headers for a header-auth request.
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
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"payload", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"payload").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(echo.method, "POST");
    assert_eq!(echo.uri, "/upsert");
    assert_eq!(echo.body, "payload");
    // The backend must NEVER see the client's auth material. The one x-dispatch-*
    // header it MAY see is the PEP-injected x-dispatch-identity — the client's own
    // auth headers (biscuit/pubkey/nonce/ts/pop) are all stripped.
    for k in echo.headers.keys() {
        assert!(
            !k.starts_with("x-dispatch-") || k == "x-dispatch-identity",
            "auth header leaked to backend: {k}"
        );
    }
    assert_eq!(
        echo.headers.get("x-dispatch-identity").map(String::as_str),
        Some(pk.as_str()),
        "the only x-dispatch-* the backend sees is the verified identity",
    );
}

#[tokio::test]
async fn query_auth_happy_path_forwards_full_query() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "GET", "/audio", b"", &nonce, NOW);
    // The signed-URL query carries the five fields plus an app param (id).
    let q = format!(
        "/audio?id=ep42&biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        NOW,
        urlenc(&pop),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(echo.method, "GET");
    // The backend receives the full query verbatim (app param survives).
    assert!(echo.uri.starts_with("/audio?id=ep42"), "uri: {}", echo.uri);
    assert!(
        echo.uri.contains("pop="),
        "auth query forwarded: {}",
        echo.uri
    );
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
    // On an authed route the backend must receive x-dispatch-identity equal to
    // the PEP-verified pubkey — so the loopback app can attribute the request to
    // an identity without holding any auth crypto or trusting a client header.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"payload", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"payload").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(
        echo.headers.get("x-dispatch-identity").map(String::as_str),
        Some(pk.as_str()),
        "backend must see the verified pubkey as x-dispatch-identity",
    );
}

#[tokio::test]
async fn forwarded_post_carries_a_single_content_length() {
    // Regression: `is_forwardable` must strip the client's Content-Length so the PEP's own
    // authoritative length is the ONLY one the backend sees. Relaying both emits a DUPLICATE
    // Content-Length — a strict backend parser (httptools/uvicorn) rejects it as malformed
    // ("Invalid HTTP request received."), while a lenient one would accept a client-forged length.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let body = b"the app payload";
    let pop = sign_http(&sk, "POST", "/upsert", body, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, body).await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(
        echo.content_length_count, 1,
        "the backend must receive EXACTLY one Content-Length (the PEP's), never the client's too",
    );
    let expected_len = body.len().to_string();
    assert_eq!(
        echo.headers.get("content-length").map(String::as_str),
        Some(expected_len.as_str()),
        "the single Content-Length must be the true buffered body length",
    );
}

#[tokio::test]
async fn client_supplied_identity_is_stripped_and_replaced() {
    // An attacker sets x-dispatch-identity itself, hoping the backend trusts it.
    // is_forwardable strips ALL client x-dispatch-* headers before the PEP adds
    // the real one, so the backend sees the VERIFIED identity, never the forged.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"payload", &nonce, NOW);
    let mut hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    hdrs.push(("x-dispatch-identity", "attacker".to_string()));
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"payload").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    let echo = r.echo();
    assert_eq!(
        echo.headers.get("x-dispatch-identity").map(String::as_str),
        Some(pk.as_str()),
        "the forged identity must be replaced with the verified pubkey",
    );
    assert_ne!(
        echo.headers.get("x-dispatch-identity").map(String::as_str),
        Some("attacker"),
        "the attacker's forged identity must never reach the backend",
    );
}

#[tokio::test]
async fn query_auth_injects_verified_identity_for_backend() {
    // Signed-URL (query-auth) reads inject the identity too — the backend can
    // attribute a media fetch to the verified owner.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "GET", "/audio", b"", &nonce, NOW);
    let q = format!(
        "/audio?id=ep42&biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        NOW,
        urlenc(&pop),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(
        r.echo().headers.get("x-dispatch-identity").map(String::as_str),
        Some(pk.as_str()),
        "query-auth must also inject the verified identity",
    );
}

#[tokio::test]
async fn passthrough_injects_no_identity() {
    // Passthrough has no verified identity, so no x-dispatch-identity may reach
    // the backend — and a client that tries to smuggle one is stripped anyway.
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

/// Write the deny-list file the PEP reads, revoking exactly these hex ids. Proves
/// the on-disk format is the contract (`{"revoked":[{"id","note","revoked_at"}]}`).
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
    // Revoke this credential's authority id.
    write_deny_list(&pep.revocation_path, &[&authority_revocation_id(&pep.root, &cred)]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 403, "revoked credential must be 403: {}", r.body);
}

#[tokio::test]
async fn revoked_credential_is_403_on_query_auth() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    write_deny_list(&pep.revocation_path, &[&authority_revocation_id(&pep.root, &cred)]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "GET", "/audio", b"", &nonce, NOW);
    let q = format!(
        "/audio?biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        NOW,
        urlenc(&pop),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(
        r.status, 403,
        "revoked signed-URL credential must be 403: {}",
        r.body
    );
}

#[tokio::test]
async fn non_revoked_credential_still_passes_with_a_populated_deny_list() {
    // A deny-list holding an UNRELATED id must not deny an unrelated credential.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    write_deny_list(&pep.revocation_path, &[&"0".repeat(64)]); // someone else
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 200, "unrelated revocation must not deny: {}", r.body);
}

#[tokio::test]
async fn revocation_live_reloads_mid_run() {
    // Write the deny-list AFTER the PEP is serving and one request has passed;
    // the very next request must be denied — no restart.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);

    // First request passes (empty deny-list).
    let nonce1 = nonce_b64();
    let pop1 = sign_http(&sk, "POST", "/upsert", b"x", &nonce1, NOW);
    let h1 = auth_headers(&cred, &pk, &nonce1, NOW, &pop1);
    let r1 = send(&pep.addr, "POST", "/upsert", &h1, b"x").await;
    assert_eq!(r1.status, 200, "passes before revocation: {}", r1.body);

    // Revoke mid-run by writing the file.
    write_deny_list(&pep.revocation_path, &[&authority_revocation_id(&pep.root, &cred)]);

    // The next request (fresh nonce, so this is a revocation denial, not a replay)
    // is denied immediately — the store live-reloaded the file.
    let nonce2 = nonce_b64();
    let pop2 = sign_http(&sk, "POST", "/upsert", b"y", &nonce2, NOW);
    let h2 = auth_headers(&cred, &pk, &nonce2, NOW, &pop2);
    let r2 = send(&pep.addr, "POST", "/upsert", &h2, b"y").await;
    assert_eq!(
        r2.status, 403,
        "the very next request after revocation must be 403: {}",
        r2.body
    );
}

// The engine-level guarantee that revoking the authority id denies EVERY
// attenuation lives in the unit test `revoking_authority_id_denies_every_
// attenuation` (src/tests.rs) — where `revocation_identifiers()` inheritance is
// asserted directly, without depending on a route whose op happens to be
// attenuation-compatible.

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
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn garbage_biscuit_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers("not-a-biscuit", &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn missing_auth_headers_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    // No auth headers at all on an authed route.
    let r = send(&pep.addr, "POST", "/upsert", &[], b"x").await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn replayed_nonce_is_401_on_second_use() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r1 = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r1.status, 200, "first should pass: {}", r1.body);
    // Exact same request (same nonce) — single-use replay must be denied.
    let r2 = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r2.status, 401, "replay must be denied: {}", r2.body);
}

#[tokio::test]
async fn stale_timestamp_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let stale = NOW - 10 * 60 * 1000; // 10 min old, window is 5 min
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, stale);
    let hdrs = auth_headers(&cred, &pk, &nonce, stale, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 401, "body: {}", r.body);
}

#[tokio::test]
async fn wrong_right_is_403() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    // Credential grants audio_get, but /upsert requires sync_write.
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await;
    assert_eq!(r.status, 403, "wrong right must be forbidden: {}", r.body);
}

// ---------- adversarial: request tampering ----------

#[tokio::test]
async fn tampered_path_breaks_pop_401() {
    let backend = start_echo().await;
    // Sign for /upsert but send to a different authed path — the canonical
    // string the PEP rebuilds won't match, so PoP fails. Both paths carry the
    // same right, so this is a PoP failure, not a routing/right failure.
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
    let pep = start_pep(&backend, two_paths, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert-evil", &hdrs, b"x").await;
    assert_eq!(r.status, 401, "tampered path must fail PoP: {}", r.body);
}

#[tokio::test]
async fn tampered_body_breaks_pop_401() {
    // FIX 1: the PoP binds the body. Sign over body A but deliver body B — the
    // canonical string the PEP rebuilds (from the hash of the DELIVERED body)
    // won't match, so PoP fails closed. This is the regression the hardening
    // closes: the transport does NOT get to protect the body.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    // Sign over body A ...
    let pop = sign_http(&sk, "POST", "/upsert", b"body-A", &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    // ... but deliver body B.
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, b"body-B").await;
    assert_eq!(r.status, 401, "tampered body must fail PoP: {}", r.body);
}

#[tokio::test]
async fn matching_body_authenticates_200() {
    // The positive counterpart: signing over the exact delivered body passes,
    // and the body reaches the backend intact.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let body = b"{\"k\":\"v\"}";
    let pop = sign_http(&sk, "POST", "/upsert", body, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, body).await;
    assert_eq!(r.status, 200, "body: {}", r.body);
    assert_eq!(r.echo().body, "{\"k\":\"v\"}");
}

#[tokio::test]
async fn tampered_query_auth_pop_is_401() {
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    // A valid PoP for /audio, then flip one base64 char of the pop param.
    let mut pop = sign_http(&sk, "GET", "/audio", b"", &nonce, NOW);
    let first = pop.remove(0);
    let flipped = if first == 'A' { 'B' } else { 'A' };
    pop.insert(0, flipped);
    let q = format!(
        "/audio?id=ep42&biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        NOW,
        urlenc(&pop),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 401, "tampered query pop must fail: {}", r.body);
}

#[tokio::test]
async fn query_auth_signed_for_other_path_is_401() {
    // A signed URL for /audio must not be replayable against /audio-secret,
    // even though both are query-auth for the same right: the path is in the
    // canonical string.
    let backend = start_echo().await;
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
    let pep = start_pep(&backend, routes, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "GET", "/audio", b"", &nonce, NOW); // signs /audio
    let q = format!(
        "/audio-secret?biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        NOW,
        urlenc(&pop),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 401, "cross-path signed URL must fail: {}", r.body);
}

// ---------- signed-URL reuse + expiry (FIX 2) ----------

#[tokio::test]
async fn signed_url_is_reusable_within_freshness_window() {
    // FIX 2: a browser <audio> element reuses ONE signed URL across range
    // requests / retries. Query-auth is freshness-only, so the SAME signed URL
    // (same nonce) must succeed more than once — it is NOT replay-rejected.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    let pop = sign_http(&sk, "GET", "/audio", b"", &nonce, NOW);
    let q = format!(
        "/audio?biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        NOW,
        urlenc(&pop),
    );
    let r1 = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r1.status, 200, "first read: {}", r1.body);
    // Reuse the EXACT same URL (same nonce) — must NOT be replay-rejected.
    let r2 = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(
        r2.status, 200,
        "reused signed URL must still pass: {}",
        r2.body
    );
}

#[tokio::test]
async fn signed_url_still_expires_when_stale() {
    // Freshness is still enforced for query-auth: a signed URL with a ts outside
    // the window is rejected, so the URL is not a permanent bearer token.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["audio_get"]);
    let nonce = nonce_b64();
    let stale = NOW - 10 * 60 * 1000; // 10 min old, window is 5 min
    let pop = sign_http(&sk, "GET", "/audio", b"", &nonce, stale);
    let q = format!(
        "/audio?biscuit={}&pubkey={}&nonce={}&ts={}&pop={}",
        urlenc(&cred),
        pk,
        urlenc(&nonce),
        stale,
        urlenc(&pop),
    );
    let r = send(&pep.addr, "GET", &q, &[], b"").await;
    assert_eq!(r.status, 401, "stale signed URL must expire: {}", r.body);
}

// ---------- adversarial: routing isolation ----------

#[tokio::test]
async fn passthrough_cannot_reach_an_authed_route() {
    // The crux invariant: a request routed to a passthrough is forwarded
    // WITHOUT auth, but it can never thereby reach an authed route's handler.
    // We give the backend an authed path and a passthrough path; a request to
    // the passthrough path reaches ONLY the passthrough path — never /upsert.
    let backend = start_echo().await;
    let pep = start_pep(&backend, ROUTES, 1000, 1 << 30).await;
    // Hitting /upsert with NO auth is denied (proves /upsert is guarded)...
    let denied = send(&pep.addr, "POST", "/upsert", &[], b"x").await;
    assert_eq!(denied.status, 401);
    // ...and the passthrough route forwards to /app-shell, not to /upsert.
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
    // /upsert is POST-only; a GET must be 405, not reach the backend or auth.
    let r = send(&pep.addr, "GET", "/upsert", &[], b"").await;
    assert_eq!(r.status, 405, "wrong method must 405: {}", r.body);
}

#[tokio::test]
async fn exact_route_wins_over_prefix() {
    // A more specific exact route must win over a covering prefix route, so an
    // app can carve a passthrough hole inside an otherwise-authed subtree
    // deterministically (longest match, order-independent).
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
    // /api/health matches BOTH; the exact passthrough wins -> no auth needed.
    let health = send(&pep.addr, "GET", "/api/health", &[], b"").await;
    assert_eq!(
        health.status, 200,
        "exact passthrough should win: {}",
        health.body
    );
    // /api/other matches only the prefix -> auth required.
    let other = send(&pep.addr, "GET", "/api/other", &[], b"").await;
    assert_eq!(
        other.status, 401,
        "prefix route stays authed: {}",
        other.body
    );
}

#[tokio::test]
async fn approve_credential_cannot_reject_or_dispatch() {
    // The parked-job decision actions use ACTION-FIRST paths (/jobs/approve/{id},
    // /jobs/reject/{id}) so each carries a DISTINCT right at the single enforcement
    // point. An approve-only credential must be able to approve but be DENIED on reject
    // and on dispatch — proving the capability split is real, not cosmetic.
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
    let cred = pep.mint(&pk, &["approve"]); // approve-only credential

    // Allowed: approve with the approve right.
    let n1 = nonce_b64();
    let p1 = sign_http(&sk, "POST", "/jobs/approve/7", b"{}", &n1, NOW);
    let h1 = auth_headers(&cred, &pk, &n1, NOW, &p1);
    let ok = send(&pep.addr, "POST", "/jobs/approve/7", &h1, b"{}").await;
    assert_eq!(ok.status, 200, "approve right may approve: {}", ok.body);

    // Denied: the SAME credential cannot reject (lacks the reject right) -> 403.
    let n2 = nonce_b64();
    let p2 = sign_http(&sk, "POST", "/jobs/reject/7", b"{}", &n2, NOW);
    let h2 = auth_headers(&cred, &pk, &n2, NOW, &p2);
    let no_reject = send(&pep.addr, "POST", "/jobs/reject/7", &h2, b"{}").await;
    assert_eq!(no_reject.status, 403, "approve right must NOT reject: {}", no_reject.body);

    // Denied: nor dispatch a new job -> 403.
    let n3 = nonce_b64();
    let p3 = sign_http(&sk, "POST", "/jobs", b"{}", &n3, NOW);
    let h3 = auth_headers(&cred, &pk, &n3, NOW, &p3);
    let no_dispatch = send(&pep.addr, "POST", "/jobs", &h3, b"{}").await;
    assert_eq!(no_dispatch.status, 403, "approve right must NOT dispatch: {}", no_dispatch.body);
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
    let nonce = nonce_b64();
    let big = vec![b'z'; 20];
    // Signed over the 20-byte body (so this is a size denial, not a PoP fail).
    let pop = sign_http(&sk, "POST", "/upsert", &big, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    // 20-byte body exceeds the 8-byte cap — caught while buffering, 413.
    let r = send(&pep.addr, "POST", "/upsert", &hdrs, &big).await;
    assert_eq!(r.status, 413, "oversize must be 413: {}", r.body);
}

#[tokio::test]
async fn oversize_body_is_413_with_no_content_length() {
    // The cap must NOT rely on Content-Length: a chunked (length-less) oversize
    // body must still be caught WHILE buffering. Proves the advisory header is
    // not the control. The backend must never see the body.
    let backend = start_echo().await;
    let pep = start_pep(&backend, CAP8_ROUTES, 1000, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    let nonce = nonce_b64();
    let big = vec![b'z'; 20];
    let pop = sign_http(&sk, "POST", "/upsert", &big, &nonce, NOW);
    let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
    // Send the body as HTTP/1.1 chunked (no Content-Length header at all).
    let r = send_chunked(&pep.addr, "POST", "/upsert", &hdrs, &big).await;
    assert_eq!(
        r.status, 413,
        "chunked oversize must be 413 (no CL to trust): {}",
        r.body
    );
}

#[tokio::test]
async fn request_quota_exhaustion_is_429() {
    let backend = start_echo().await;
    // Allow only 2 requests per minute.
    let pep = start_pep(&backend, ROUTES, 2, 1 << 30).await;
    let (sk, pk) = holder();
    let cred = pep.mint(&pk, &["sync_write"]);
    // Two authed requests succeed; the third trips the per-identity quota.
    let mut last = 0u16;
    for _ in 0..3 {
        let nonce = nonce_b64();
        let pop = sign_http(&sk, "POST", "/upsert", b"x", &nonce, NOW);
        let hdrs = auth_headers(&cred, &pk, &nonce, NOW, &pop);
        last = send(&pep.addr, "POST", "/upsert", &hdrs, b"x").await.status;
    }
    assert_eq!(last, 429, "quota should be exhausted by the 3rd request");
}

// ---------- route-table validation (boot-time) ----------

#[test]
fn route_table_rejects_ambiguous_matcher() {
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["GET"]
path = "/x"
prefix = "/x"
auth = "passthrough"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
    assert!(spec.resolve().is_err(), "path+prefix must be rejected");
}

#[test]
fn route_table_rejects_authed_route_without_right() {
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["POST"]
path = "/x"
auth = "header"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
    assert!(spec.resolve().is_err(), "header auth needs a right");
}

#[test]
fn route_table_rejects_passthrough_with_right() {
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["GET"]
path = "/x"
auth = "passthrough"
right = "sneaky"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
    assert!(spec.resolve().is_err(), "passthrough must take no right");
}

#[test]
fn route_table_rejects_unknown_auth() {
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["GET"]
path = "/x"
auth = "magic"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
    assert!(
        spec.resolve().is_err(),
        "unknown auth mode must be rejected"
    );
}

#[test]
fn route_table_rejects_query_auth_on_mutating_method() {
    // FIX 2: query-auth is freshness-only (reusable), so a mutating signed URL
    // could be replayed within the window — it must be GET/HEAD only, at boot.
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["POST"]
path = "/x"
auth = "query"
right = "audio_get"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
    assert!(
        spec.resolve().is_err(),
        "query auth on POST must be rejected"
    );
}

#[test]
fn route_table_allows_query_auth_on_get_and_head() {
    let toml = r#"
backend = "http://127.0.0.1:1"
[[routes]]
methods = ["GET", "HEAD"]
path = "/audio"
auth = "query"
right = "audio_get"
"#;
    let spec: RouteTableSpec = toml::from_str(toml).unwrap();
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
