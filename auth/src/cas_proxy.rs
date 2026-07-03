//! The CAS enforcement proxy: it verifies Biscuit + PoP on every blob request,
//! enforces per-blob size caps and per-identity quotas, and STREAMS bytes to the
//! backend store (bazel-remote) without buffering whole blobs. The backend sees
//! only pre-authenticated loopback traffic and holds no auth crypto.

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
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;

type BoxedBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// How the backend store names blobs. The PEP's own surface is always
/// `/blobs/sha256/<hex>`; the backend path may differ.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BackendStyle {
    /// Forward `/blobs/sha256/<hex>` verbatim (MinIO-style / the test stub).
    Passthrough,
    /// Rewrite to `/cas/<hex>` (bazel-remote's HTTP CAS surface).
    Bazel,
}

impl BackendStyle {
    pub fn parse(s: &str) -> Self {
        match s {
            "bazel" => BackendStyle::Bazel,
            _ => BackendStyle::Passthrough,
        }
    }
    fn path(&self, hexaddr: &str) -> String {
        match self {
            BackendStyle::Passthrough => format!("/blobs/sha256/{hexaddr}"),
            BackendStyle::Bazel => format!("/cas/{hexaddr}"),
        }
    }
}

/// Configuration for the CAS proxy.
#[derive(Clone)]
pub struct CasConfig {
    pub backend: String,     // e.g. http://127.0.0.1:9092
    pub max_blob_bytes: u64, // per-PUT cap
    pub style: BackendStyle, // backend blob-path convention
}

/// The CAS proxy (cheaply cloneable — shared state is behind Arc).
#[derive(Clone)]
pub struct CasProxy {
    root_pub: PublicKey,
    nonces: NonceStore,
    cfg: CasConfig,
    quota: Quota,
    client: Client<HttpConnector, BoxedBody>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl CasProxy {
    pub fn new(
        root_pub: PublicKey,
        nonces: NonceStore,
        cfg: CasConfig,
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
                    log::warn!("cas: accept: {e}");
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
                    log::debug!("cas: connection: {e}");
                }
            });
        }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<BoxedBody> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Only the blob surface exists; no LIST/DELETE.
        let hexaddr = match parse_blob_path(&path) {
            Some(h) => h,
            None => return text(StatusCode::NOT_FOUND, "not_found"),
        };
        match method {
            Method::GET | Method::HEAD | Method::PUT => {}
            _ => return text(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
        }

        // Build the authenticated request from headers.
        let areq = match extract_auth(&req, &method, &path, &hexaddr) {
            Ok(a) => a,
            Err(e) => return deny(&method, &path, e),
        };
        let now = (self.now)();
        // CAS is single-use: every blob request consumes its nonce.
        let identity = match verify(&self.root_pub, &self.nonces, now, &areq, true) {
            Ok(id) => id,
            Err(e) => return deny(&method, &path, e),
        };

        // Per-PUT size cap (Content-Length is required by the CAS contract).
        if method == Method::PUT {
            match req
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                Some(n) if n > self.cfg.max_blob_bytes => {
                    log::warn!("cas: 413 oversize put {} bytes by {}", n, identity.id);
                    return text(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
                }
                Some(n) => {
                    if !self.quota.allow(&identity.id, n, now) {
                        log::warn!("cas: 429 quota exceeded by {}", identity.id);
                        return text(StatusCode::TOO_MANY_REQUESTS, "quota_exceeded");
                    }
                }
                None => return text(StatusCode::BAD_REQUEST, "content_length_required"),
            }
        } else if !self.quota.allow(&identity.id, 0, now) {
            log::warn!("cas: 429 request quota exceeded by {}", identity.id);
            return text(StatusCode::TOO_MANY_REQUESTS, "quota_exceeded");
        }

        // Forward to the backend, streaming the body through (no buffering).
        // The backend blob path may differ from the PEP's own surface.
        let backend_uri = format!(
            "{}{}",
            self.cfg.backend.trim_end_matches('/'),
            self.cfg.style.path(&hexaddr)
        );
        let (parts, body) = req.into_parts();
        let boxed: BoxedBody = body
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            .boxed();
        let mut fwd = Request::builder().method(parts.method).uri(backend_uri);
        if let Some(cl) = parts.headers.get(hyper::header::CONTENT_LENGTH) {
            fwd = fwd.header(hyper::header::CONTENT_LENGTH, cl);
        }
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
                log::warn!("cas: backend error: {e}");
                text(StatusCode::BAD_GATEWAY, "backend_unreachable")
            }
        }
    }
}

/// Parse /blobs/sha256/<64 hex> -> the hex, or None.
fn parse_blob_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/blobs/sha256/")?;
    if rest.len() == 64
        && rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Some(rest.to_string())
    } else {
        None
    }
}

fn header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

fn extract_auth(
    req: &Request<Incoming>,
    method: &Method,
    path: &str,
    hexaddr: &str,
) -> Result<AuthedRequest, AuthError> {
    let biscuit = header(req, "x-dispatch-biscuit")
        .ok_or_else(|| AuthError::Malformed("missing biscuit".into()))?;
    let pubkey = header(req, "x-dispatch-pubkey")
        .ok_or_else(|| AuthError::Malformed("missing pubkey".into()))?;
    let nonce = header(req, "x-dispatch-nonce")
        .ok_or_else(|| AuthError::Malformed("missing nonce".into()))?;
    let ts = header(req, "x-dispatch-ts")
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AuthError::Malformed("missing ts".into()))?;
    let sig =
        header(req, "x-dispatch-pop").ok_or_else(|| AuthError::Malformed("missing pop".into()))?;
    Ok(AuthedRequest {
        op: Op::Cas {
            method: method.to_string(),
            path: path.to_string(),
        },
        biscuit_b64: biscuit.to_string(),
        pubkey_hex: pubkey.to_string(),
        nonce_b64: nonce.to_string(),
        ts_ms: ts,
        pop_sig_b64: sig.to_string(),
        required_lanes: vec![],
        address_hex: Some(hexaddr.to_string()),
    })
}

/// Map an auth denial to an HTTP status, logging it as a first-class outcome.
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
    log::warn!("cas: {} {} denied: {}", method, path, e);
    text(status, &format!("{e}"))
}

fn text(status: StatusCode, msg: &str) -> Response<BoxedBody> {
    let body: BoxedBody = Full::new(Bytes::from(msg.to_string()))
        .map_err(|e: Infallible| match e {})
        .boxed();
    Response::builder().status(status).body(body).unwrap()
}
