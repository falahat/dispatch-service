//! The PEP: the single in-path enforcement point. It fronts BOTH tailnet
//! surfaces — the dispatcher's runner surface (framed) and the CAS (HTTP) —
//! verifying Biscuit + PoP and forwarding pre-authenticated traffic to the
//! co-located backends over loopback. It holds only the root PUBLIC key.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::PublicKey;
use dispatch_auth::cas_proxy::{CasConfig, CasProxy};
use dispatch_auth::frame_proxy::FrameProxy;
use dispatch_auth::nonce::NonceStore;
use dispatch_auth::quota::Quota;
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

    let dispatcher_addr = env("PEP_DISPATCHER_ADDR", "127.0.0.1:7700");
    let cas_backend = env("PEP_CAS_BACKEND", "http://127.0.0.1:9092");
    let runner_listen = env("PEP_RUNNER_LISTEN", "0.0.0.0:7443");
    let cas_listen = env("PEP_CAS_LISTEN", "0.0.0.0:8443");
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
        dispatcher_addr.clone(),
        now.clone(),
    );
    let quota = Quota::new(max_req, max_bytes);
    let cas = CasProxy::new(
        root_pub,
        nonces.clone(),
        CasConfig {
            backend: cas_backend.clone(),
            max_blob_bytes,
        },
        quota,
        now.clone(),
    );

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
    let _ = tokio::join!(f, c);
}
