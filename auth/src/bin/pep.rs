//! The PEP: the single in-path enforcement point. It fronts the tailnet
//! surfaces — the dispatcher's runner surface (framed), the CAS (HTTP), and,
//! optionally, an app's generic HTTP surface (route-table driven) — verifying
//! Biscuit + PoP and forwarding pre-authenticated traffic to the co-located
//! backends over loopback. It holds only the root PUBLIC key.
//!
//! Each surface is served IFF its env is explicitly configured — there is NO
//! default that silently opens a listener. So the plane PEP (runner + cas env)
//! serves those two, while an app PEP like easy-podcast's `sync-pep` (only the
//! http env) serves ONLY http — it never opens a dead-end runner/cas port on
//! the tailnet netns it shares with the coordinator.

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

/// Which surfaces to serve, decided from the environment. Each is `Some((listen,
/// backend))` iff configured — a surface with only one of its two vars set is a
/// config bug, and a PEP that would serve nothing is a misconfiguration.
#[derive(Debug, PartialEq, Eq)]
struct SurfacePlan {
    runner: Option<(String, String)>, // (listen, dispatcher addr)
    cas: Option<(String, String)>,    // (listen, backend url)
    http: Option<(String, String)>,   // (listen, route-table path)
}

/// Resolve the surface plan from an env lookup. Each surface is served IFF BOTH
/// its vars are set; only one set is an error; none at all is an error. Pure
/// over `get`, so it is unit-testable without touching the process environment.
fn plan_surfaces(get: impl Fn(&str) -> Option<String>) -> Result<SurfacePlan, String> {
    let pair = |listen_key: &str, backend_key: &str| -> Result<Option<(String, String)>, String> {
        match (get(listen_key), get(backend_key)) {
            (Some(listen), Some(backend)) => Ok(Some((listen, backend))),
            (None, None) => Ok(None),
            _ => Err(format!("set BOTH {listen_key} and {backend_key}, or neither")),
        }
    };
    let plan = SurfacePlan {
        runner: pair("PEP_RUNNER_LISTEN", "PEP_DISPATCHER_ADDR")?,
        cas: pair("PEP_CAS_LISTEN", "PEP_CAS_BACKEND")?,
        http: pair("PEP_HTTP_LISTEN", "PEP_HTTP_ROUTES")?,
    };
    if plan.runner.is_none() && plan.cas.is_none() && plan.http.is_none() {
        return Err("no surface configured — set at least one of runner \
             (PEP_RUNNER_LISTEN+PEP_DISPATCHER_ADDR), cas (PEP_CAS_LISTEN+PEP_CAS_BACKEND), \
             or http (PEP_HTTP_LISTEN+PEP_HTTP_ROUTES)"
            .to_string());
    }
    Ok(plan)
}

/// Bind a surface listener or exit(1) with a clear message.
async fn bind(listen: &str, surface: &str) -> TcpListener {
    TcpListener::bind(listen).await.unwrap_or_else(|e| {
        eprintln!("pep: bind {surface} surface {listen}: {e}");
        std::process::exit(1);
    })
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

    // Decide which surfaces to serve BEFORE opening anything — a half- or un-
    // configured PEP fails at boot, never silently opens a dead-end listener.
    let plan = plan_surfaces(|k| std::env::var(k).ok()).unwrap_or_else(|e| {
        eprintln!("pep: {e}");
        std::process::exit(2);
    });

    let nonce_db = env("PEP_NONCE_DB", "pep-nonces.redb");
    let window_ms: i64 = env("PEP_FRESHNESS_MS", "300000").parse().unwrap_or(300_000);
    let nonces = NonceStore::open(&nonce_db, window_ms).unwrap_or_else(|e| {
        eprintln!("pep: nonce store: {e}");
        std::process::exit(1);
    });

    // The live-reloaded credential deny-list, shared across the served surfaces
    // (like the nonce store). A missing file means nothing is revoked; writing
    // the file at runtime denies the very next request that bears a revoked
    // credential, with no PEP restart.
    let revocation_db = env("PEP_REVOCATION_DB", "pep-revocations.json");
    let revocations = RevocationStore::open(&revocation_db).unwrap_or_else(|e| {
        eprintln!("pep: revocation store {revocation_db}: {e}");
        std::process::exit(1);
    });

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

    // Bind + serve exactly the configured surfaces. Nothing else opens a port.
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if let Some((listen, dispatcher_addr)) = plan.runner {
        let frame = FrameProxy::new(
            root_pub,
            nonces.clone(),
            revocations.clone(),
            dispatcher_addr.clone(),
            now.clone(),
        );
        let ln = bind(&listen, "runner").await;
        log::info!("pep: runner surface {listen} -> {dispatcher_addr}");
        handles.push(tokio::spawn(frame.serve(ln)));
    }

    if let Some((listen, cas_backend)) = plan.cas {
        let max_blob_bytes: u64 = env("PEP_MAX_BLOB_BYTES", &(8u64 << 30).to_string())
            .parse()
            .unwrap_or(8 << 30);
        let max_req: u32 = env("PEP_MAX_REQ_PER_MIN", "6000").parse().unwrap_or(6000);
        let max_bytes: u64 = env("PEP_MAX_BYTES_PER_MIN", &(64u64 << 30).to_string())
            .parse()
            .unwrap_or(64 << 30);
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
            Quota::new(max_req, max_bytes),
            now.clone(),
        );
        let ln = bind(&listen, "cas").await;
        log::info!("pep: cas surface {listen} -> {cas_backend}");
        handles.push(tokio::spawn(cas.serve(ln)));
    }

    if let Some((listen, routes_path)) = plan.http {
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
        let http_max_req: u32 = env("PEP_HTTP_MAX_REQ_PER_MIN", "6000")
            .parse()
            .unwrap_or(6000);
        let http_max_bytes: u64 = env("PEP_HTTP_MAX_BYTES_PER_MIN", &(4u64 << 30).to_string())
            .parse()
            .unwrap_or(4 << 30);
        let proxy = HttpProxy::new(
            root_pub,
            nonces.clone(),
            revocations.clone(),
            cfg,
            Quota::new(http_max_req, http_max_bytes),
            now.clone(),
        );
        let ln = bind(&listen, "http").await;
        log::info!("pep: http surface {listen} -> {backend}");
        handles.push(tokio::spawn(proxy.serve(ln)));
    }

    for h in handles {
        let _ = h.await;
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_surfaces, SurfacePlan};
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn http_only_serves_exactly_the_http_surface() {
        // easy-podcast's sync-pep sets ONLY the http env — it must not open a
        // runner/cas listener (the tailnet dead-end ports this closes).
        let plan = plan_surfaces(env_of(&[
            ("PEP_HTTP_LISTEN", "127.0.0.1:9443"),
            ("PEP_HTTP_ROUTES", "/etc/dispatch/sync-routes.toml"),
        ]))
        .unwrap();
        assert!(plan.runner.is_none(), "http-only must not open a runner listener");
        assert!(plan.cas.is_none(), "http-only must not open a cas listener");
        assert_eq!(
            plan.http,
            Some((
                "127.0.0.1:9443".to_string(),
                "/etc/dispatch/sync-routes.toml".to_string()
            ))
        );
    }

    #[test]
    fn plane_pep_serves_runner_and_cas_but_not_http() {
        let plan = plan_surfaces(env_of(&[
            ("PEP_RUNNER_LISTEN", "0.0.0.0:7443"),
            ("PEP_DISPATCHER_ADDR", "dispatcher:7700"),
            ("PEP_CAS_LISTEN", "0.0.0.0:8443"),
            ("PEP_CAS_BACKEND", "http://cas:8080"),
        ]))
        .unwrap();
        assert!(plan.runner.is_some());
        assert!(plan.cas.is_some());
        assert!(plan.http.is_none(), "the plane PEP must not open an http listener");
    }

    #[test]
    fn a_half_configured_surface_is_a_boot_error() {
        // One var without its partner is a config bug, never a silent default.
        assert!(plan_surfaces(env_of(&[("PEP_RUNNER_LISTEN", "0.0.0.0:7443")])).is_err());
        assert!(plan_surfaces(env_of(&[("PEP_CAS_BACKEND", "http://cas:8080")])).is_err());
        assert!(plan_surfaces(env_of(&[("PEP_HTTP_LISTEN", "127.0.0.1:9443")])).is_err());
    }

    #[test]
    fn no_surface_configured_is_a_boot_error() {
        assert!(plan_surfaces(env_of(&[])).is_err());
    }
}
