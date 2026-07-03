//! The generic HTTP enforcement proxy: it fronts an arbitrary loopback HTTP
//! backend (an app's Flask/FastAPI server) and, per a static per-app route
//! table, enforces Biscuit + PoP on each request before forwarding it. The
//! backend sees only pre-authenticated loopback traffic and holds no auth
//! crypto — like `CasProxy`, but the capability for each (method, path) is named
//! by the route table rather than a fixed CAS convention.
//!
//! The PoP binds method + path + the FULL request body:
//!   `http/v0 <METHOD> <path> <sha256hex(body)> <nonce> <ts>`
//! On an authed route the PEP buffers the body under a HARD cap (413 if the cap
//! is hit WHILE reading — the advisory Content-Length is never trusted), hashes
//! it, verifies, then forwards the buffered bytes. We do NOT trust the transport
//! to protect the body. This is the small app-JSON surface; large blobs stay on
//! the streaming CAS. Response bodies still stream straight back, unbuffered.
//!
//! Three auth modes per route.
//!
//! `Header(right)`: the five PoP fields ride in `x-dispatch-*` headers — the
//! standard authed (mutating) API call. SINGLE-USE: the nonce is consumed, so an
//! exact replay is rejected.
//!
//! `Query(right)`: the same five fields ride in the query string, for signed-URL
//! GET/HEAD reads (`GET /audio?...&pop=...`). Method + path are bound (the body
//! is empty → `sha256hex(b"")`); the query is NOT bound (the auth fields cannot
//! sign themselves). FRESHNESS-ONLY: the ts must be within the window (so the URL
//! EXPIRES) but the nonce is not stored, so a browser reusing one signed URL
//! across range requests / retries is not replay-rejected. Query-auth is
//! restricted to idempotent GET/HEAD at route-table boot time.
//!
//! `Passthrough`: forwarded unauthenticated (app-shell GET, the enrollment
//! redeem endpoint). A passthrough route can never satisfy an authed route:
//! routing is decided once, before auth, by longest-match, so a request is
//! authed iff the route it matched says so.

use crate::cred::{verify, AuthedRequest};
use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::quota::Quota;
use crate::Op;
use biscuit_auth::PublicKey;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;

type BoxedBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// A per-request body cap, enforced by counting bytes WHILE buffering (not by
/// trusting Content-Length): the body is rejected 413 the moment it exceeds this.
/// The HTTP surface is small app JSON — large blobs belong on the streaming CAS.
const DEFAULT_MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// How a matched route is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAuth {
    /// Require capability `right`, auth fields in `x-dispatch-*` headers.
    Header(String),
    /// Require capability `right`, auth fields in the query string.
    Query(String),
    /// Forward unauthenticated.
    Passthrough,
}

/// One route: a set of methods plus a path matcher and an auth mode.
#[derive(Debug, Clone)]
pub struct Route {
    pub methods: Vec<Method>,
    pub matcher: PathMatcher,
    pub auth: RouteAuth,
}

/// How a route's path is matched against a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatcher {
    /// Exact match on the full path (no query).
    Exact(String),
    /// Match when the request path equals `p` or starts with `p` followed by
    /// `/` (so `/audio` matches `/audio` and `/audio/x`, never `/audioX`).
    Prefix(String),
}

impl PathMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Exact(p) => path == p,
            PathMatcher::Prefix(p) => {
                path == p
                    || path
                        .strip_prefix(p)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
        }
    }

    /// Specificity for longest-match ordering: an exact match beats a prefix,
    /// and a longer prefix beats a shorter one.
    fn specificity(&self) -> (u8, usize) {
        match self {
            PathMatcher::Exact(p) => (1, p.len()),
            PathMatcher::Prefix(p) => (0, p.len()),
        }
    }
}

/// The resolved route table for one app's HTTP surface.
#[derive(Clone)]
pub struct RouteTable {
    routes: Arc<Vec<Route>>,
}

impl RouteTable {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes: Arc::new(routes),
        }
    }

    /// Resolve `(method, path)` to its route by longest, most-specific match.
    /// A method mismatch on an otherwise-matching path is a distinct outcome so
    /// the caller can answer 405 vs 404 correctly.
    fn resolve(&self, method: &Method, path: &str) -> Resolution<'_> {
        let mut best: Option<&Route> = None;
        let mut path_seen = false;
        for r in self.routes.iter() {
            if !r.matcher.matches(path) {
                continue;
            }
            path_seen = true;
            if !r.methods.iter().any(|m| m == method) {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => r.matcher.specificity() > b.matcher.specificity(),
            };
            if better {
                best = Some(r);
            }
        }
        match best {
            Some(r) => Resolution::Route(r),
            None if path_seen => Resolution::MethodNotAllowed,
            None => Resolution::NotFound,
        }
    }
}

enum Resolution<'a> {
    Route(&'a Route),
    MethodNotAllowed,
    NotFound,
}

/// Serde shape for one route in a route-table file (TOML/JSON). Phases 3 & 5
/// author these; see `docs/PEP_HTTP.md` for the format.
#[derive(Debug, Deserialize)]
pub struct RouteSpec {
    /// HTTP methods this route serves, e.g. `["GET"]`, `["POST", "PUT"]`.
    pub methods: Vec<String>,
    /// Exact-path matcher. Exactly one of `path` / `prefix` must be set.
    #[serde(default)]
    pub path: Option<String>,
    /// Path-prefix matcher (segment-boundary). Exactly one of `path` / `prefix`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// One of `header`, `query`, `passthrough`.
    pub auth: String,
    /// Required capability for `header`/`query` auth; omitted for `passthrough`.
    #[serde(default)]
    pub right: Option<String>,
}

/// Serde shape for a whole route-table file.
#[derive(Debug, Deserialize)]
pub struct RouteTableSpec {
    /// Loopback backend base URL, e.g. `http://127.0.0.1:5000`.
    pub backend: String,
    /// Ordered routes (order is irrelevant to matching — longest match wins).
    pub routes: Vec<RouteSpec>,
    /// Optional per-request body cap in bytes (default 64 MiB).
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
}

/// A route-table parse error, surfaced at boot (never at request time).
#[derive(Debug)]
pub struct RouteTableError(pub String);

impl std::fmt::Display for RouteTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "route table: {}", self.0)
    }
}

impl std::error::Error for RouteTableError {}

impl RouteTableSpec {
    /// Validate + resolve a spec into an `HttpConfig`. Rejects an ambiguous or
    /// incomplete route so a misconfiguration fails at boot, not in the path.
    pub fn resolve(self) -> std::result::Result<HttpConfig, RouteTableError> {
        let mut routes = Vec::with_capacity(self.routes.len());
        for (i, spec) in self.routes.into_iter().enumerate() {
            let where_ = || format!("route[{i}]");
            let matcher = match (spec.path, spec.prefix) {
                (Some(p), None) => PathMatcher::Exact(p),
                (None, Some(p)) => PathMatcher::Prefix(p),
                (Some(_), Some(_)) => {
                    return Err(RouteTableError(format!(
                        "{}: set exactly one of `path` or `prefix`",
                        where_()
                    )))
                }
                (None, None) => {
                    return Err(RouteTableError(format!(
                        "{}: missing `path` or `prefix`",
                        where_()
                    )))
                }
            };
            let (PathMatcher::Exact(p) | PathMatcher::Prefix(p)) = &matcher;
            if !p.starts_with('/') {
                return Err(RouteTableError(format!(
                    "{}: path must start with '/'",
                    where_()
                )));
            }
            let mut methods = Vec::with_capacity(spec.methods.len());
            for m in &spec.methods {
                let parsed = Method::from_bytes(m.as_bytes())
                    .map_err(|_| RouteTableError(format!("{}: bad method {:?}", where_(), m)))?;
                methods.push(parsed);
            }
            if methods.is_empty() {
                return Err(RouteTableError(format!("{}: no methods", where_())));
            }
            let auth = match spec.auth.as_str() {
                "header" => RouteAuth::Header(require_right(spec.right, &where_())?),
                "query" => RouteAuth::Query(require_right(spec.right, &where_())?),
                "passthrough" => {
                    if spec.right.is_some() {
                        return Err(RouteTableError(format!(
                            "{}: passthrough takes no `right`",
                            where_()
                        )));
                    }
                    RouteAuth::Passthrough
                }
                other => {
                    return Err(RouteTableError(format!(
                        "{}: unknown auth {:?} (want header|query|passthrough)",
                        where_(),
                        other
                    )))
                }
            };
            // Query-auth (signed URLs) is freshness-only (reusable until expiry),
            // so it MUST be an idempotent read — a mutating signed URL could be
            // replayed within the window. Restrict it to GET/HEAD at boot.
            if matches!(auth, RouteAuth::Query(_))
                && !methods
                    .iter()
                    .all(|m| m == Method::GET || m == Method::HEAD)
            {
                return Err(RouteTableError(format!(
                    "{}: query auth is GET/HEAD only (signed URLs are reusable reads)",
                    where_()
                )));
            }
            routes.push(Route {
                methods,
                matcher,
                auth,
            });
        }
        Ok(HttpConfig {
            backend: self.backend,
            table: RouteTable::new(routes),
            max_body_bytes: self.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
        })
    }
}

fn require_right(
    right: Option<String>,
    where_: &str,
) -> std::result::Result<String, RouteTableError> {
    match right {
        Some(r) if !r.is_empty() => Ok(r),
        _ => Err(RouteTableError(format!(
            "{where_}: header/query auth requires a non-empty `right`"
        ))),
    }
}

/// Configuration for the HTTP proxy: one loopback backend plus its route table.
#[derive(Clone)]
pub struct HttpConfig {
    pub backend: String,
    pub table: RouteTable,
    pub max_body_bytes: u64,
}

/// The generic HTTP proxy (cheaply cloneable — shared state is behind Arc).
#[derive(Clone)]
pub struct HttpProxy {
    root_pub: PublicKey,
    nonces: NonceStore,
    cfg: HttpConfig,
    quota: Quota,
    client: Client<HttpConnector, BoxedBody>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl HttpProxy {
    pub fn new(
        root_pub: PublicKey,
        nonces: NonceStore,
        cfg: HttpConfig,
        quota: Quota,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http::<BoxedBody>();
        Self {
            root_pub,
            nonces,
            cfg,
            quota,
            client,
            now,
        }
    }

    /// Serve until the listener errors (or forever).
    pub async fn serve(self, listener: TcpListener) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("http: accept: {e}");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let proxy = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let p = proxy.clone();
                    async move { Ok::<_, Infallible>(p.handle(req).await) }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    log::debug!("http: connection: {e}");
                }
            });
        }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<BoxedBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Routing is decided ONCE, before any auth, from (method, path) only.
        // Whether a request is authenticated is a property of the matched route,
        // so a passthrough route can never be used to reach an authed one.
        let auth = match self.cfg.table.resolve(&method, &path) {
            Resolution::Route(r) => r.auth.clone(),
            Resolution::MethodNotAllowed => {
                return text(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
            }
            Resolution::NotFound => return text(StatusCode::NOT_FOUND, "not_found"),
        };

        // Split headers/query (needed for auth) from the body (buffered next).
        let (parts, body) = req.into_parts();

        // Buffer the body under a HARD cap, counting bytes as we read — the
        // advisory Content-Length is never trusted (a lying or absent header
        // cannot smuggle an oversize body past the cap). This binds the body:
        // its hash goes into the PoP canonical string. The cap applies to every
        // route, including passthrough, so no open path is an unbounded sink.
        let buffered = match buffer_capped(body, self.cfg.max_body_bytes).await {
            Ok(b) => b,
            Err(BufferError::TooLarge) => {
                log::warn!("http: 413 oversize body on {method} {path}");
                return text(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
            }
            Err(BufferError::Read) => return text(StatusCode::BAD_REQUEST, "body_read"),
        };
        let body_sha256_hex = hex::encode(Sha256::digest(&buffered));

        // Enforce, if the route demands it. On success we hold the identity for
        // quota accounting; passthrough attributes to a fixed anonymous bucket.
        // Header-auth is single-use (mutating); query-auth is freshness-only
        // (reusable signed-URL read, but still expires).
        let id = match &auth {
            RouteAuth::Passthrough => "anon".to_string(),
            RouteAuth::Header(right) => {
                let areq =
                    match extract_auth_headers(&parts, &method, &path, right, &body_sha256_hex) {
                        Ok(a) => a,
                        Err(e) => return deny(&method, &path, e),
                    };
                match self.authenticate(&areq, true) {
                    Ok(identity) => identity,
                    Err(e) => return deny(&method, &path, e),
                }
            }
            RouteAuth::Query(right) => {
                let areq = match extract_auth_query(&parts, &method, &path, right, &body_sha256_hex)
                {
                    Ok(a) => a,
                    Err(e) => return deny(&method, &path, e),
                };
                match self.authenticate(&areq, false) {
                    Ok(identity) => identity,
                    Err(e) => return deny(&method, &path, e),
                }
            }
        };

        // Rolling per-identity quota on the actual buffered body size.
        let now = (self.now)();
        if !self.quota.allow(&id, buffered.len() as u64, now) {
            log::warn!("http: 429 quota exceeded by {id}");
            return text(StatusCode::TOO_MANY_REQUESTS, "quota_exceeded");
        }

        self.forward(parts, buffered).await
    }

    /// Verify a built request against the shared engine (UNCHANGED `verify()`).
    fn authenticate(&self, areq: &AuthedRequest, single_use: bool) -> Result<String, AuthError> {
        let now = (self.now)();
        verify(&self.root_pub, &self.nonces, now, areq, single_use).map(|id| id.id)
    }

    /// Forward the buffered request to the loopback backend, preserving method,
    /// the full path+query, and the (already-read) body. The response body still
    /// streams straight back, unbuffered.
    async fn forward(
        &self,
        parts: hyper::http::request::Parts,
        body: Bytes,
    ) -> Response<BoxedBody> {
        let path = parts.uri.path();
        let pq = match parts.uri.query() {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        };
        let backend_uri = format!("{}{}", self.cfg.backend.trim_end_matches('/'), pq);
        let body_len = body.len();
        let boxed: BoxedBody = Full::new(body).map_err(|e: Infallible| match e {}).boxed();
        let mut fwd = Request::builder().method(&parts.method).uri(backend_uri);
        // Forward the app-relevant headers, minus the auth headers (already
        // consumed) and hop-by-hop headers. We drop the client's Content-Length /
        // Transfer-Encoding and set the true buffered length ourselves, so a
        // lying length can never reach the backend.
        for (name, value) in parts.headers.iter() {
            if is_forwardable(name.as_str()) {
                fwd = fwd.header(name, value);
            }
        }
        fwd = fwd.header(hyper::header::CONTENT_LENGTH, body_len);
        let fwd = match fwd.body(boxed) {
            Ok(r) => r,
            Err(e) => {
                return text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("proxy_build: {e}"),
                )
            }
        };
        match self.client.request(fwd).await {
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                let boxed: BoxedBody = body
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed();
                Response::from_parts(parts, boxed)
            }
            Err(e) => {
                log::warn!("http: backend error: {e}");
                text(StatusCode::BAD_GATEWAY, "backend_unreachable")
            }
        }
    }
}

/// Why buffering a request body failed.
enum BufferError {
    /// The body exceeded the cap while reading (before it finished).
    TooLarge,
    /// The underlying stream errored.
    Read,
}

/// Read a request body fully into memory, aborting the instant the accumulated
/// size exceeds `max`. Never allocates more than `max` + one frame — a lying or
/// absent Content-Length cannot force an unbounded buffer.
async fn buffer_capped(body: Incoming, max: u64) -> std::result::Result<Bytes, BufferError> {
    let mut body = body;
    let mut acc: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BufferError::Read)?;
        if let Some(chunk) = frame.data_ref() {
            if acc.len() as u64 + chunk.len() as u64 > max {
                return Err(BufferError::TooLarge);
            }
            acc.extend_from_slice(chunk);
        }
    }
    Ok(Bytes::from(acc))
}

/// Auth headers are consumed by the PEP; hop-by-hop headers must not be relayed.
fn is_forwardable(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("x-dispatch-") {
        return false;
    }
    !matches!(
        lower.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

fn header<'a>(parts: &'a hyper::http::request::Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

/// Build an `AuthedRequest` from the `x-dispatch-*` headers.
fn extract_auth_headers(
    parts: &hyper::http::request::Parts,
    method: &Method,
    path: &str,
    right: &str,
    body_sha256_hex: &str,
) -> Result<AuthedRequest, AuthError> {
    let biscuit = header(parts, "x-dispatch-biscuit")
        .ok_or_else(|| AuthError::Malformed("missing biscuit".into()))?;
    let pubkey = header(parts, "x-dispatch-pubkey")
        .ok_or_else(|| AuthError::Malformed("missing pubkey".into()))?;
    let nonce = header(parts, "x-dispatch-nonce")
        .ok_or_else(|| AuthError::Malformed("missing nonce".into()))?;
    let ts = header(parts, "x-dispatch-ts")
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AuthError::Malformed("missing ts".into()))?;
    let sig = header(parts, "x-dispatch-pop")
        .ok_or_else(|| AuthError::Malformed("missing pop".into()))?;
    Ok(build_areq(
        method,
        path,
        right,
        body_sha256_hex,
        biscuit,
        pubkey,
        nonce,
        ts,
        sig,
    ))
}

/// Build an `AuthedRequest` from the query string (signed-URL auth). The five
/// fields are named `biscuit`, `pubkey`, `nonce`, `ts`, `pop`. The PoP binds
/// method + path + body (empty for a GET/HEAD read); the query is unbound.
fn extract_auth_query(
    parts: &hyper::http::request::Parts,
    method: &Method,
    path: &str,
    right: &str,
    body_sha256_hex: &str,
) -> Result<AuthedRequest, AuthError> {
    let q = parts
        .uri
        .query()
        .ok_or_else(|| AuthError::Malformed("missing query auth".into()))?;
    let mut biscuit = None;
    let mut pubkey = None;
    let mut nonce = None;
    let mut ts = None;
    let mut pop = None;
    for (k, v) in url_query_pairs(q) {
        match k.as_str() {
            "biscuit" => biscuit = Some(v),
            "pubkey" => pubkey = Some(v),
            "nonce" => nonce = Some(v),
            "ts" => ts = v.parse::<i64>().ok(),
            "pop" => pop = Some(v),
            _ => {}
        }
    }
    let biscuit = biscuit.ok_or_else(|| AuthError::Malformed("missing biscuit".into()))?;
    let pubkey = pubkey.ok_or_else(|| AuthError::Malformed("missing pubkey".into()))?;
    let nonce = nonce.ok_or_else(|| AuthError::Malformed("missing nonce".into()))?;
    let ts = ts.ok_or_else(|| AuthError::Malformed("missing ts".into()))?;
    let pop = pop.ok_or_else(|| AuthError::Malformed("missing pop".into()))?;
    Ok(build_areq(
        method,
        path,
        right,
        body_sha256_hex,
        &biscuit,
        &pubkey,
        &nonce,
        ts,
        &pop,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_areq(
    method: &Method,
    path: &str,
    right: &str,
    body_sha256_hex: &str,
    biscuit: &str,
    pubkey: &str,
    nonce: &str,
    ts: i64,
    pop: &str,
) -> AuthedRequest {
    AuthedRequest {
        op: Op::Http {
            method: method.to_string(),
            path: path.to_string(),
            right: right.to_string(),
            body_sha256_hex: body_sha256_hex.to_string(),
        },
        biscuit_b64: biscuit.to_string(),
        pubkey_hex: pubkey.to_string(),
        nonce_b64: nonce.to_string(),
        ts_ms: ts,
        pop_sig_b64: pop.to_string(),
        required_lanes: vec![],
        address_hex: None,
    }
}

/// Minimal, dependency-free `application/x-www-form-urlencoded` pair decoding
/// for the query string. Decodes `%XX` and `+`; a malformed escape yields the
/// literal bytes, which can never forge a valid PoP (the canonical string is
/// rebuilt from method + path + body hash, not the query).
fn url_query_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Map an auth denial to an HTTP status — byte-for-byte the `cas_proxy::deny`
/// policy so both surfaces answer denials identically.
fn deny(method: &Method, path: &str, e: AuthError) -> Response<BoxedBody> {
    let status = match e {
        AuthError::Malformed(_) | AuthError::Freshness | AuthError::Replay => {
            StatusCode::UNAUTHORIZED
        }
        AuthError::PopFailed
        | AuthError::BiscuitSignature
        | AuthError::MissingPubkey
        | AuthError::MissingIdentity => StatusCode::UNAUTHORIZED,
        AuthError::Denied(_) => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    log::warn!("http: {method} {path} denied: {e}");
    text(status, &format!("{e}"))
}

fn text(status: StatusCode, msg: &str) -> Response<BoxedBody> {
    let body: BoxedBody = Full::new(Bytes::from(msg.to_string()))
        .map_err(|e: Infallible| match e {})
        .boxed();
    Response::builder().status(status).body(body).unwrap()
}
