//! The generic HTTP enforcement proxy: it fronts an arbitrary loopback HTTP
//! backend (an app's Flask/FastAPI server) and, per a static per-app route
//! table, enforces Biscuit + a DPoP proof on each request before forwarding it.
//! The backend sees only pre-authenticated loopback traffic and holds no auth
//! crypto — like `CasProxy`, but the capability for each (method, path) is named
//! by the route table rather than a fixed CAS convention.
//!
//! The per-request proof is an RFC 9449 **DPoP proof JWT** (see [`crate::dpop`]),
//! which binds method + URI + the presented Biscuit + the FULL request body (a
//! `content-digest` claim). On an authed route the PEP buffers the body under a
//! HARD cap (413 if the cap is hit WHILE reading — the advisory Content-Length is
//! never trusted), hashes it, verifies the proof against the hash, then forwards
//! the buffered bytes. We do NOT trust the transport to protect the body. This is
//! the small app-JSON surface; large blobs stay on the streaming CAS. Response
//! bodies still stream straight back, unbuffered.
//!
//! The `htu` the proof must match is rebuilt by the PEP from its CONFIGURED public
//! origin plus the request path — never from a client `Host`/`X-Forwarded-*`
//! header (TLS terminates at the Serve edge, so those are untrusted here).
//!
//! Three auth modes per route.
//!
//! `Header(right)`: the Biscuit rides in `Authorization: DPoP <biscuit>` and the
//! proof in the `DPoP:` header — the standard authed (mutating) API call.
//! SINGLE-USE: the proof `jti` is consumed, so an exact replay is rejected.
//!
//! `Query(right)`: the Biscuit + proof ride in the `biscuit` / `dpop` query params,
//! for signed-URL GET/HEAD reads (`GET /audio?...&dpop=...`) where a browser
//! `<audio>`/`<img>` can't set headers. The proof binds an empty body; its `htu`
//! is the path (no query), so the auth params don't sign themselves. FRESHNESS-ONLY:
//! the `iat` must be within the window (so the URL EXPIRES) but the `jti` is not
//! stored, so a browser reusing one signed URL across range requests / retries is
//! not replay-rejected. Query-auth is restricted to idempotent GET/HEAD at
//! route-table boot time.
//!
//! `Passthrough`: forwarded unauthenticated (app-shell GET, the enrollment
//! redeem endpoint). A passthrough route can never satisfy an authed route:
//! routing is decided once, before auth, by longest-match, so a request is
//! authed iff the route it matched says so.

use crate::cred::{verify_http_dpop, DpopHttpRequest};
use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::quota::Quota;
use crate::revocation::RevocationStore;
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
    /// The PEP's public origin (scheme + host, no path), e.g.
    /// `https://easypod.tail46021f.ts.net`. REQUIRED: the DPoP `htu` a proof must
    /// match is rebuilt from this + the request path, so it is a trusted config
    /// value, never a client header. A missing origin fails at boot.
    pub origin: String,
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
        // The public origin the DPoP `htu` is rebuilt from must be a real
        // scheme+authority; a bare host or an empty value would make every proof's
        // `htu` unverifiable. Trailing slash is trimmed so `<origin><path>` never
        // doubles it (`location.origin` never has one).
        let origin = self.origin.trim_end_matches('/').to_string();
        if origin.is_empty() || !origin.contains("://") {
            return Err(RouteTableError(format!(
                "origin must be a scheme+host like https://host.example (got {:?})",
                self.origin
            )));
        }
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
            // A default-open catch-all must be inexpressible: under segment-boundary
            // matching `prefix = "/"` matches only the bare root while READING as
            // "everything" — the config that means it wants `path = "/"`, and every
            // published path named explicitly.
            if matches!(&matcher, PathMatcher::Prefix(p) if p == "/") {
                return Err(RouteTableError(format!(
                    "{}: `prefix = \"/\"` is rejected (it matches only \"/\" and reads as a catch-all); use `path = \"/\"` and name each published path",
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
            origin,
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

/// Configuration for the HTTP proxy: the public origin (for DPoP `htu`), one
/// loopback backend, and the route table.
#[derive(Clone)]
pub struct HttpConfig {
    pub origin: String,
    pub backend: String,
    pub table: RouteTable,
    pub max_body_bytes: u64,
}

/// The generic HTTP proxy (cheaply cloneable — shared state is behind Arc).
#[derive(Clone)]
pub struct HttpProxy {
    root_pub: PublicKey,
    nonces: NonceStore,
    revocations: RevocationStore,
    cfg: HttpConfig,
    quota: Quota,
    client: Client<HttpConnector, BoxedBody>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl HttpProxy {
    pub fn new(
        root_pub: PublicKey,
        nonces: NonceStore,
        revocations: RevocationStore,
        cfg: HttpConfig,
        quota: Quota,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http::<BoxedBody>();
        Self {
            root_pub,
            nonces,
            revocations,
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
        let body_sha256: [u8; 32] = Sha256::digest(&buffered).into();

        // The DPoP `htu` a proof must match: the PEP's CONFIGURED public origin +
        // the request path (no query). Rebuilt here, NEVER taken from a client
        // Host/X-Forwarded header — TLS terminates at the Serve edge, so those are
        // untrusted at this hop.
        let htu = format!("{}{}", self.cfg.origin, path);

        // Enforce, if the route demands it. On success we hold the identity for
        // quota accounting; passthrough attributes to a fixed anonymous bucket.
        // Header-auth is single-use (mutating); query-auth is freshness-only
        // (reusable signed-URL read, but still expires). `verified` is the
        // authenticated pubkey to hand the backend on an authed route, and None
        // on passthrough (there is no verified identity to inject).
        let query_auth = matches!(auth, RouteAuth::Query(_));
        let (id, verified): (String, Option<String>) = match &auth {
            RouteAuth::Passthrough => ("anon".to_string(), None),
            RouteAuth::Header(right) => {
                let dreq = match extract_dpop_headers(&parts, &method, &htu, right, body_sha256) {
                    Ok(d) => d,
                    Err(e) => return deny(&method, &path, e),
                };
                match self.authenticate(&dreq, true) {
                    Ok(identity) => (identity.clone(), Some(identity)),
                    Err(e) => return deny(&method, &path, e),
                }
            }
            RouteAuth::Query(right) => {
                let dreq = match extract_dpop_query(&parts, &method, &htu, right, body_sha256) {
                    Ok(d) => d,
                    Err(e) => return deny(&method, &path, e),
                };
                match self.authenticate(&dreq, false) {
                    Ok(identity) => (identity.clone(), Some(identity)),
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

        self.forward(parts, buffered, verified.as_deref(), query_auth)
            .await
    }

    /// Verify a built DPoP request against the shared engine (`verify_http_dpop`).
    fn authenticate(&self, dreq: &DpopHttpRequest, single_use: bool) -> Result<String, AuthError> {
        let now = (self.now)();
        verify_http_dpop(
            &self.root_pub,
            &self.nonces,
            &self.revocations,
            now,
            dreq,
            single_use,
        )
        .map(|id| id.id)
    }

    /// Forward the buffered request to the backend. Query-auth credentials are
    /// consumed here; application query parameters survive unchanged.
    ///
    /// `verified` is the authenticated pubkey (hex) on an authed route, or None
    /// on passthrough. When present, it is injected as `x-dispatch-identity` AFTER
    /// the client headers are copied — and `is_forwardable` strips every client
    /// `x-dispatch-*` header first, so a client cannot spoof this: the backend
    /// sees exactly the identity the PEP verified, or (on passthrough) none at all.
    async fn forward(
        &self,
        parts: hyper::http::request::Parts,
        body: Bytes,
        verified: Option<&str>,
        strip_query_auth: bool,
    ) -> Response<BoxedBody> {
        let path = parts.uri.path();
        let pq = match parts.uri.query() {
            Some(q) if strip_query_auth => {
                let query = query_without_auth(q);
                if query.is_empty() {
                    path.to_string()
                } else {
                    format!("{path}?{query}")
                }
            }
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
        // Inject the verified identity for the backend (authed routes only). The
        // client's own x-dispatch-* headers were already stripped above, so this
        // is the sole source of the header the backend sees.
        if let Some(id) = verified {
            fwd = fwd.header("x-dispatch-identity", id);
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
    // Every client `x-dispatch-*` is stripped so the backend can't be handed a
    // forged identity — the PEP injects the ONE `x-dispatch-identity` it verified
    // (in `forward`, after this filter).
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
            // The DPoP credential (`Authorization: DPoP <biscuit>`) and proof (`DPoP:`)
            // are consumed here — they never reach the backend, which holds no auth crypto.
            | "authorization"
            | "dpop"
            // The PEP re-buffers the body and sets the authoritative Content-Length itself
            // (see `forward`). Relaying the client's would emit a DUPLICATE Content-Length: a
            // strict backend parser (httptools/uvicorn) rejects that as a malformed request,
            // and it would let a lying client length reach a lenient backend. The PEP owns it.
            | "content-length"
    )
}

fn header<'a>(parts: &'a hyper::http::request::Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

/// Assemble a `DpopHttpRequest` for a header-auth call: the Biscuit rides in
/// `Authorization: DPoP <biscuit>` and the proof JWT in the `DPoP:` header.
fn extract_dpop_headers(
    parts: &hyper::http::request::Parts,
    method: &Method,
    htu: &str,
    right: &str,
    body_sha256: [u8; 32],
) -> Result<DpopHttpRequest, AuthError> {
    let authz = header(parts, "authorization")
        .ok_or_else(|| AuthError::Malformed("missing authorization".into()))?;
    let biscuit = dpop_scheme_token(authz)
        .ok_or_else(|| AuthError::Malformed("authorization is not `DPoP <biscuit>`".into()))?;
    let proof =
        header(parts, "dpop").ok_or_else(|| AuthError::Malformed("missing dpop proof".into()))?;
    Ok(DpopHttpRequest {
        method: method.to_string(),
        htu: htu.to_string(),
        right: right.to_string(),
        biscuit_b64: biscuit.to_string(),
        proof_jwt: proof.to_string(),
        body_sha256,
    })
}

/// Assemble a `DpopHttpRequest` for a signed-URL read: the Biscuit + proof ride in
/// the `biscuit` / `dpop` query params (a browser `<audio>`/`<img>` can't set
/// headers). The proof's `htu` is the path only, so the query — which carries the
/// auth — is not part of what the proof signs.
fn extract_dpop_query(
    parts: &hyper::http::request::Parts,
    method: &Method,
    htu: &str,
    right: &str,
    body_sha256: [u8; 32],
) -> Result<DpopHttpRequest, AuthError> {
    let q = parts
        .uri
        .query()
        .ok_or_else(|| AuthError::Malformed("missing query auth".into()))?;
    let mut biscuit = None;
    let mut proof = None;
    for (k, v) in url_query_pairs(q) {
        match k.as_str() {
            "biscuit" => biscuit = Some(v),
            "dpop" => proof = Some(v),
            _ => {}
        }
    }
    let biscuit = biscuit.ok_or_else(|| AuthError::Malformed("missing biscuit".into()))?;
    let proof = proof.ok_or_else(|| AuthError::Malformed("missing dpop proof".into()))?;
    Ok(DpopHttpRequest {
        method: method.to_string(),
        htu: htu.to_string(),
        right: right.to_string(),
        biscuit_b64: biscuit,
        proof_jwt: proof,
        body_sha256,
    })
}

/// Parse an `Authorization: DPoP <token>` value, returning the token iff the scheme
/// is `DPoP` (case-insensitive, per RFC 9110) and the token is non-empty.
fn dpop_scheme_token(authz: &str) -> Option<&str> {
    let (scheme, token) = authz.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("dpop") && !token.is_empty()).then_some(token)
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

/// Remove the query credentials consumed by a query-auth route while preserving
/// every application parameter byte-for-byte.
fn query_without_auth(q: &str) -> String {
    q.split('&')
        .filter(|pair| {
            let key = pair.split_once('=').map_or(*pair, |(key, _)| key);
            !matches!(percent_decode(key).as_str(), "biscuit" | "dpop")
        })
        .collect::<Vec<_>>()
        .join("&")
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
        | AuthError::DpopFailed(_)
        | AuthError::BiscuitSignature
        | AuthError::MissingPubkey
        | AuthError::MissingIdentity => StatusCode::UNAUTHORIZED,
        AuthError::Denied(_) | AuthError::Revoked => StatusCode::FORBIDDEN,
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
