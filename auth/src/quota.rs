//! Per-identity rolling quotas: a bound on requests and bytes per minute, so a
//! single enrolled identity cannot exhaust the CAS or use it as a probing
//! oracle at volume. In-memory (rate limiting need not survive a restart).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Quota {
    inner: Arc<Mutex<HashMap<String, Vec<(i64, u64)>>>>, // id -> [(ts_ms, bytes)]
    max_requests_per_min: u32,
    max_bytes_per_min: u64,
}

impl Quota {
    pub fn new(max_requests_per_min: u32, max_bytes_per_min: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_requests_per_min,
            max_bytes_per_min,
        }
    }

    /// Record a request of `bytes` for `id` at `now_ms` if within the rolling
    /// window limits; returns false (and records nothing) when a limit is hit.
    pub fn allow(&self, id: &str, bytes: u64, now_ms: i64) -> bool {
        let cutoff = now_ms - 60_000;
        let mut guard = self.inner.lock().unwrap();
        let events = guard.entry(id.to_string()).or_default();
        events.retain(|(ts, _)| *ts > cutoff);
        let req_count = events.len() as u32;
        let byte_sum: u64 = events.iter().map(|(_, b)| *b).sum();
        if req_count + 1 > self.max_requests_per_min {
            return false;
        }
        if byte_sum + bytes > self.max_bytes_per_min {
            return false;
        }
        events.push((now_ms, bytes));
        true
    }
}
