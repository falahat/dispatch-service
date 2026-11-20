//! Per-lease narrowing of runner credentials. A credential that grants `right("lease")` may
//! read (GET) only the blobs of a job it holds a live lease on: the job's invocation, each
//! input, and each file of a manifest input. It may look a blob up (HEAD) or store one (PUT)
//! only while it holds a live lease. Other credentials, such as an application's, are not
//! narrowed.
//!
//! The frame proxy records each grant it relays before the runner sees it. A lease ends when
//! the runner sends complete, fail or release for it. A heartbeat reply renews it, unless the
//! reply tells the runner to abandon the job; a lease not renewed expires after its TTL.

use crate::cas_proxy::CasConfig;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

const MAX_INVOCATION_BYTES: usize = 1 << 20;
const MAX_MANIFEST_BYTES: usize = 64 << 20;
const MAX_INPUTS: usize = 64;
const MAX_MANIFEST_ENTRIES: usize = 65536;

struct Lease {
    job_id: String,
    ttl_ms: i64,
    expires_ms: i64,
    abandoned: bool,
    reads: HashSet<String>,
}

/// The live leases of every runner identity, shared by the frame and CAS proxies.
#[derive(Clone)]
pub struct LeaseBook {
    leases: Arc<Mutex<HashMap<String, HashMap<String, Lease>>>>,
    cfg: CasConfig,
    client: Client<HttpConnector, Empty<Bytes>>,
}

impl LeaseBook {
    /// `cfg` names the CAS backend the book reads invocations and manifests from.
    pub fn new(cfg: CasConfig) -> Self {
        Self {
            leases: Arc::new(Mutex::new(HashMap::new())),
            cfg,
            client: Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>(),
        }
    }

    /// Update the book from one relayed runner frame and the dispatcher's reply to it.
    pub async fn observe(&self, runner: &str, verb: &str, request: &[u8], reply: &[u8], now: i64) {
        let (Ok(request), Ok(reply)) = (
            serde_json::from_slice::<Value>(request),
            serde_json::from_slice::<Value>(reply),
        ) else {
            return;
        };
        let asked = &request["body"];
        let answer = &reply["body"];
        let lease_id = asked["lease_id"].as_str().unwrap_or("");
        match (verb, reply["type"].as_str().unwrap_or("")) {
            ("lease", "grant") => {
                let lease = &answer["lease"];
                let job = &answer["job"];
                let (Some(lease_id), Some(job_id), Some(ttl_s), Some(invocation)) = (
                    lease["lease_id"].as_str(),
                    job["job_id"].as_str(),
                    lease["ttl_s"].as_i64(),
                    job["invocation_address"].as_str().and_then(address_hex),
                ) else {
                    return;
                };
                let reads = self.job_reads(&invocation).await;
                let mut leases = self.leases.lock().unwrap();
                leases.entry(runner.to_string()).or_default().insert(
                    lease_id.to_string(),
                    Lease {
                        job_id: job_id.to_string(),
                        ttl_ms: ttl_s.saturating_mul(1000),
                        expires_ms: now.saturating_add(ttl_s.saturating_mul(1000)),
                        abandoned: false,
                        reads,
                    },
                );
            }
            ("heartbeat", "beat_ok") => {
                let abandon: HashSet<&str> = answer["directives"]
                    .as_array()
                    .map(|all| {
                        all.iter()
                            .filter(|d| d["kind"] == "abandon")
                            .filter_map(|d| d["job_id"].as_str())
                            .collect()
                    })
                    .unwrap_or_default();
                let mut leases = self.leases.lock().unwrap();
                if let Some(held) = leases.get_mut(runner) {
                    for lease in held.values_mut() {
                        if abandon.contains(lease.job_id.as_str()) {
                            lease.abandoned = true;
                        }
                    }
                    if let Some(lease) = held.get_mut(lease_id) {
                        if !lease.abandoned && lease.expires_ms > now {
                            lease.expires_ms = now.saturating_add(lease.ttl_ms);
                        }
                    }
                }
            }
            ("complete" | "fail" | "release", _) => {
                let mut leases = self.leases.lock().unwrap();
                if let Some(held) = leases.get_mut(runner) {
                    held.remove(lease_id);
                    if held.is_empty() {
                        leases.remove(runner);
                    }
                }
            }
            _ => {}
        }
    }

    /// Whether `runner` holds a live lease whose job reads blob `hex`.
    pub fn may_read(&self, runner: &str, hex: &str, now: i64) -> bool {
        self.live(runner, now, |lease| lease.reads.contains(hex))
    }

    /// Whether `runner` holds any live lease.
    pub fn holds_lease(&self, runner: &str, now: i64) -> bool {
        self.live(runner, now, |_| true)
    }

    fn live(&self, runner: &str, now: i64, wanted: impl Fn(&Lease) -> bool) -> bool {
        let mut leases = self.leases.lock().unwrap();
        let Some(held) = leases.get_mut(runner) else {
            return false;
        };
        held.retain(|_, lease| lease.expires_ms > now);
        let found = held.values().any(wanted);
        if held.is_empty() {
            leases.remove(runner);
        }
        found
    }

    /// The blobs a job reads: its invocation, each input, and each file of a manifest input.
    /// A blob the backend lacks or that does not parse adds nothing more; the runner then
    /// fails to fetch it and releases the job.
    async fn job_reads(&self, invocation: &str) -> HashSet<String> {
        let mut reads = HashSet::from([invocation.to_string()]);
        let Some(invocation) = self.fetch_json(invocation, MAX_INVOCATION_BYTES).await else {
            return reads;
        };
        let Some(inputs) = invocation["inputs"].as_object() else {
            return reads;
        };
        for input in inputs.values().take(MAX_INPUTS) {
            let Some(hex) = input["address"].as_str().and_then(address_hex) else {
                continue;
            };
            reads.insert(hex.clone());
            if input["kind"] != "manifest" {
                continue;
            }
            if let Some(manifest) = self.fetch_json(&hex, MAX_MANIFEST_BYTES).await {
                if let Some(entries) = manifest["entries"].as_array() {
                    reads.extend(
                        entries
                            .iter()
                            .take(MAX_MANIFEST_ENTRIES)
                            .filter_map(|entry| entry["address"].as_str().and_then(address_hex)),
                    );
                }
            }
        }
        reads
    }

    async fn fetch_json(&self, hex: &str, limit: usize) -> Option<Value> {
        let uri = format!(
            "{}{}",
            self.cfg.backend.trim_end_matches('/'),
            self.cfg.style.path(hex)
        );
        let request = Request::get(uri).body(Empty::new()).ok()?;
        let response = self.client.request(request).await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body = Limited::new(response.into_body(), limit)
            .collect()
            .await
            .ok()?
            .to_bytes();
        if hex::encode(Sha256::digest(&body)) != hex {
            return None;
        }
        serde_json::from_slice(&body).ok()
    }
}

/// The 64 lowercase hex digits of a `sha256:` address, or None.
fn address_hex(address: &str) -> Option<String> {
    let hex = address.strip_prefix("sha256:")?;
    (hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| hex.to_string())
}
