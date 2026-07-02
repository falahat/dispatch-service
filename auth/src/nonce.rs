//! Durable, single-use nonce store. A PoP is valid once: replaying the same
//! (nonce, ts) is denied even across a PEP restart, which is what makes the
//! "replay across restart" attack fail closed. Backed by redb (pure Rust, no C).

use crate::error::{AuthError, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

// nonce (base64 string) -> the ts it was first seen at (ms).
const NONCES: TableDefinition<&str, i64> = TableDefinition::new("nonces");

/// Default freshness window: a PoP timestamp must be within this of server time.
pub const DEFAULT_WINDOW_MS: i64 = 300_000; // 5 minutes

/// A durable single-use nonce store.
#[derive(Clone)]
pub struct NonceStore {
    db: Arc<Database>,
    window_ms: i64,
}

impl NonceStore {
    /// Open (creating if needed) a nonce store at `path`.
    pub fn open<P: AsRef<Path>>(path: P, window_ms: i64) -> Result<Self> {
        let db = Database::create(path).map_err(|e| AuthError::Store(e.to_string()))?;
        // Ensure the table exists.
        let wtx = db
            .begin_write()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        {
            wtx.open_table(NONCES)
                .map_err(|e| AuthError::Store(e.to_string()))?;
        }
        wtx.commit().map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(Self {
            db: Arc::new(db),
            window_ms,
        })
    }

    /// Check freshness and single-use in one write transaction. A stale/future
    /// ts is `Freshness`; a seen nonce is `Replay`; otherwise the nonce is
    /// recorded and Ok is returned.
    pub fn check_and_store(&self, nonce_b64: &str, ts_ms: i64, now_ms: i64) -> Result<()> {
        if (now_ms - ts_ms).abs() > self.window_ms {
            return Err(AuthError::Freshness);
        }
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let replay;
        {
            let mut table = wtx
                .open_table(NONCES)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            // Scope the read guard so it drops before the mutable insert.
            replay = table
                .get(nonce_b64)
                .map_err(|e| AuthError::Store(e.to_string()))?
                .is_some();
            if !replay {
                table
                    .insert(nonce_b64, ts_ms)
                    .map_err(|e| AuthError::Store(e.to_string()))?;
            }
        }
        wtx.commit().map_err(|e| AuthError::Store(e.to_string()))?;
        if replay {
            return Err(AuthError::Replay);
        }
        Ok(())
    }

    /// Prune nonces older than the freshness window — they can never be replayed
    /// successfully again (freshness would reject them), so they are dead weight.
    pub fn prune(&self, now_ms: i64) -> Result<usize> {
        let cutoff = now_ms - self.window_ms;
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let mut removed = 0usize;
        {
            let mut table = wtx
                .open_table(NONCES)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            let mut stale: Vec<String> = Vec::new();
            {
                let iter = table.iter().map_err(|e| AuthError::Store(e.to_string()))?;
                for entry in iter {
                    let (k, v) = entry.map_err(|e| AuthError::Store(e.to_string()))?;
                    if v.value() < cutoff {
                        stale.push(k.value().to_string());
                    }
                }
            }
            for k in stale {
                table
                    .remove(k.as_str())
                    .map_err(|e| AuthError::Store(e.to_string()))?;
                removed += 1;
            }
        }
        wtx.commit().map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(removed)
    }
}
