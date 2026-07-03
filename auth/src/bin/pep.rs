//! The PEP: the single in-path enforcement point. It fronts the tailnet
//! surfaces — the dispatcher's runner surface (framed), the CAS (HTTP), and,
//! optionally, an app's generic HTTP surface (route-table driven) — verifying
//! Biscuit + PoP and forwarding pre-authenticated traffic to the co-located
//! backends over loopback. It holds only the root PUBLIC key.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::PublicKey;
use dispatch_auth::cas_proxy::{BackendStyle, CasConfig, CasProxy};
use dispatch_auth::frame_proxy::FrameProxy;
use dispatch_auth::http_proxy::{HttpProxy, RouteTableSpec};
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::quota::Quota;
use dispatch_auth::revocation::RevocationStore;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_req(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("pep: required env {key} is unset");
        std::process::exit(2);
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let root_b64 = env_req("PEP_ROOT_PUBKEY");
    let root_bytes = STANDARD.decode(root_b64.trim()).unwrap_or_else(|e| {
        eprintln!("pep: PEP_ROOT_PUBKEY not base64: {e}");
        std::process::exit(2);
    });
    let root_pub = PublicKey::from_bytes(&root_bytes).unwrap_or_else(|e| {
        eprintln!("pep: invalid root public key: {e}");
        std::process::exit(2);
    });

    let nonce_db = env("PEP_NONCE_DB", "pep-nonces.redb");
    let window_ms: i64 = env("PEP_FRESHNESS_MS", "300000").parse().unwrap_or(300_000);
    let nonces = NonceStore::open(&nonce_db, window_ms).unwrap_or_else(|e| {
        eprintln!("pep: nonce store: {e}");
        std::process::exit(1);
    });

    // The live-reloaded credential deny-list, shared across all three surfaces
    // (like the nonce store). A missing file means nothing is revoked; writing
    // the file at runtime denies the very next request that bears a revoked
    // credential, with no PEP restart.
    let revocation_db = env("PEP_REVOCATION_DB", "pep-revocations.json");
    let revocations = RevocationStore::open(&revocation_db).unwrap_or_else(|e| {
        eprintln!("pep: revocation store {revocation_db}: {e}");
        std::process::exit(1);
    });

    let dispatcher_addr = env("PEP_DISPATCHER_ADDR", "127.0.0.1:7700");
    let cas_backend = env("PEP_CAS_BACKEND", "http://127.0.0.1:9092");
    let runner_listen = env("PEP_RUNNER_LISTEN", "0.0.0.0:7443");
    let cas_listen = env("PEP_CAS_LISTEN", "0.0.0.0:8443");
    // Optional generic HTTP surface (app API). Both the route table AND the
    // listen address must be set for it to come up — absent = surface not served.
    let http_routes = std::env::var("PEP_HTTP_ROUTES").ok();
    let http_listen = std::env::var("PEP_HTTP_LISTEN").ok();
    let http_max_req: u32 = env("PEP_HTTP_MAX_REQ_PER_MIN", "6000")
        .parse()
        .unwrap_or(6000);
    let http_max_bytes: u64 = env(
        "PEP_HTTP_MAX_BYTES_PER_MIN",
        &(4u64 * 1024 * 1024 * 1024).to_string(),
    )
    .parse()
    .unwrap_or(4 << 30);
    let max_blob_bytes: u64 = env(
        "PEP_MAX_BLOB_BYTES",
        &(8u64 * 1024 * 1024 * 1024).to_string(),
    )
    .parse()
    .unwrap_or(8 << 30);
    let max_req: u32 = env("PEP_MAX_REQ_PER_MIN", "6000").parse().unwrap_or(6000);
    let max_bytes: u64 = env(
        "PEP_MAX_BYTES_PER_MIN",
        &(64u64 * 1024 * 1024 * 1024).to_string(),
    )
    .parse()
    .unwrap_or(64 << 30);

    let now: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(now_ms);

    // Periodic nonce prune (dead nonces can never replay successfully anyway).
    {
        let nonces = nonces.clone();
        let now = now.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                if let Err(e) = nonces.prune(now()) {
                    log::warn!("pep: nonce prune: {e}");
                }
            }
        });
    }

    let frame = FrameProxy::new(
        root_pub,
        nonces.clone(),
        revocations.clone(),
        dispatcher_addr.clone(),
        now.clone(),
    );
    let quota = Quota::new(max_req, max_bytes);
    let style = BackendStyle::parse(&env("PEP_CAS_STYLE", "passthrough"));
    let cas = CasProxy::new(
        root_pub,
        nonces.clone(),
        revocations.clone(),
        CasConfig {
            backend: cas_backend.clone(),
            max_blob_bytes,
            style,
        },
        quota,
        now.clone(),
    );

    // Build the optional generic HTTP surface if configured. A malformed route
    // table is a boot failure, never a request-time surprise.
    let http = match (http_routes, http_listen) {
        (Some(routes_path), Some(listen)) => {
            let raw = std::fs::read_to_string(&routes_path).unwrap_or_else(|e| {
                eprintln!("pep: read http route table {routes_path}: {e}");
                std::process::exit(2);
            });
            let spec: RouteTableSpec = toml::from_str(&raw).unwrap_or_else(|e| {
                eprintln!("pep: parse http route table {routes_path}: {e}");
                std::process::exit(2);
            });
            let cfg = spec.resolve().unwrap_or_else(|e| {
                eprintln!("pep: {e}");
                std::process::exit(2);
            });
            let backend = cfg.backend.clone();
            let http_quota = Quota::new(http_max_req, http_max_bytes);
            let proxy = HttpProxy::new(
                root_pub,
                nonces.clone(),
                revocations.clone(),
                cfg,
                http_quota,
                now.clone(),
            );
            Some((proxy, listen, backend))
        }
        (None, None) => None,
        _ => {
            eprintln!("pep: set BOTH PEP_HTTP_ROUTES and PEP_HTTP_LISTEN, or neither");
            std::process::exit(2);
        }
    };

    let frame_ln = TcpListener::bind(&runner_listen).await.unwrap_or_else(|e| {
        eprintln!("pep: bind runner surface {runner_listen}: {e}");
        std::process::exit(1);
    });
    let cas_ln = TcpListener::bind(&cas_listen).await.unwrap_or_else(|e| {
        eprintln!("pep: bind cas surface {cas_listen}: {e}");
        std::process::exit(1);
    });

    log::info!("pep: runner surface {runner_listen} -> {dispatcher_addr}; cas surface {cas_listen} -> {cas_backend}");
    let f = tokio::spawn(frame.serve(frame_ln));
    let c = tokio::spawn(cas.serve(cas_ln));

    let h = if let Some((proxy, listen, backend)) = http {
        let http_ln = TcpListener::bind(&listen).await.unwrap_or_else(|e| {
            eprintln!("pep: bind http surface {listen}: {e}");
            std::process::exit(1);
        });
        log::info!("pep: http surface {listen} -> {backend}");
        Some(tokio::spawn(proxy.serve(http_ln)))
    } else {
        None
    };

    match h {
        Some(h) => {
            let _ = tokio::join!(f, c, h);
        }
        None => {
            let _ = tokio::join!(f, c);
        }
    }
}
