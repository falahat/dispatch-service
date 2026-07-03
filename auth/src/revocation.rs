//! Live-reloaded credential deny-list. A credential is revoked by putting one of
//! its Biscuit *revocation identifiers* (per-block signature bytes, lowercase
//! hex) on this list; the PEP then denies any request bearing that credential.
//!
//! Design (mirrors `NonceStore`'s shape — cheaply `Clone`, `Arc`-shared, injected
//! into `verify()` and each proxy): a small JSON file on disk, reloaded when its
//! mtime changes, so an operator can revoke a credential by writing the file and
//! have the *very next* request denied, with no PEP restart. Reads are lock-cheap
//! and the on-disk set is cached between mtime changes.
//!
//! File format:
//! ```json
//! { "revoked": [ { "id": "<lowercase-hex>", "note": "...", "revoked_at": 0 } ] }
//! ```
//! `id` is a Biscuit revocation identifier (from `Biscuit::revocation_identifiers`),
//! lowercase hex. A **missing** file means nothing is revoked (not an error). A
//! present-but-malformed file keeps the last-known-good set (a revocation is never
//! *lost* to a transient bad write) and is logged — fail closed, never open.

use crate::error::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// One deny-list entry: a revoked credential's revocation identifier plus audit
/// metadata. `id` is lowercase hex of a Biscuit block signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedEntry {
    /// A Biscuit revocation identifier (lowercase hex).
    pub id: String,
    /// Free-form operator note (why it was revoked).
    #[serde(default)]
    pub note: String,
    /// When it was revoked (ms since epoch), for audit.
    #[serde(default)]
    pub revoked_at: i64,
}

/// The on-disk deny-list document.
#[derive(Debug, Default, Serialize, Deserialize)]
struct DenyListFile {
    #[serde(default)]
    revoked: Vec<RevokedEntry>,
}

/// The disk fingerprint used to detect a change without re-reading: mtime AND
/// length. Length is the tiebreaker for coarse mtime resolution — revoking only
/// ever *grows* the file, so a same-tick write is still detected. `None` means
/// the file was absent at the last read.
type Stamp = Option<(SystemTime, u64)>;

/// The cached view of the file: the fingerprint it was read at and the set of
/// revoked ids (lowercase hex) for O(1) membership.
struct Cache {
    stamp: Stamp,
    ids: HashSet<String>,
}

/// The current disk fingerprint of `path` (mtime + length), or `None` if absent.
fn stamp_of(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    Some((mtime, meta.len()))
}

/// A live-reloaded credential deny-list (cheaply cloneable — shared behind Arc).
#[derive(Clone)]
pub struct RevocationStore {
    path: Arc<PathBuf>,
    cache: Arc<RwLock<Cache>>,
}

impl RevocationStore {
    /// Open the deny-list at `path`, loading it once. A missing file is fine
    /// (nothing revoked); a malformed present file is an error at open time (so a
    /// bad file is caught at boot, not silently ignored).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (stamp, ids) = match std::fs::read(&path) {
            Ok(data) => {
                let file: DenyListFile = serde_json::from_slice(&data)
                    .map_err(|e| AuthError::Malformed(format!("deny-list: {e}")))?;
                (stamp_of(&path), Self::index(&file))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, HashSet::new()),
            Err(e) => return Err(AuthError::Io(e.to_string())),
        };
        Ok(Self {
            path: Arc::new(path),
            cache: Arc::new(RwLock::new(Cache { stamp, ids })),
        })
    }

    /// Build the id set from a parsed file (ids lowercased so hex comparison is
    /// case-insensitive regardless of how the file was written).
    fn index(file: &DenyListFile) -> HashSet<String> {
        file.revoked
            .iter()
            .map(|e| e.id.trim().to_ascii_lowercase())
            .filter(|id| !id.is_empty())
            .collect()
    }

    /// Reload from disk if the file's mtime changed since the last read (or the
    /// file appeared / disappeared). Keeps the last-known-good set on a read or
    /// parse error, so a transient bad write never *drops* a live revocation.
    fn refresh_if_changed(&self) {
        let current = stamp_of(self.path.as_path());
        // Fast path: fingerprint unchanged (both present-and-equal, or both absent).
        {
            let cache = self.cache.read().expect("revocation cache poisoned");
            if cache.stamp == current {
                return;
            }
        }
        // Slow path: the file changed. Re-read + re-parse under the write lock.
        let mut cache = self.cache.write().expect("revocation cache poisoned");
        // Re-check under the write lock (another thread may have just reloaded).
        if cache.stamp == current {
            return;
        }
        match std::fs::read(self.path.as_path()) {
            Ok(data) => match serde_json::from_slice::<DenyListFile>(&data) {
                Ok(file) => {
                    cache.ids = Self::index(&file);
                    cache.stamp = stamp_of(self.path.as_path());
                }
                Err(e) => {
                    log::warn!(
                        "revocation: keeping last-known-good; {} is malformed: {e}",
                        self.path.display()
                    );
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The file DISAPPEARED at runtime (it existed at the last read — the
                // stamp changed from Some to None). RETAIN the last-known-good set:
                // a deleted deny-list must never fail OPEN by silently dropping live
                // revocations (an accidental unmount / botched deploy would otherwise
                // un-revoke a revoked credential). Set the stamp to absent so we don't
                // re-read on every request, but keep the ids until the file reappears.
                // To CLEAR revocations, write an explicit empty `{"revoked":[]}` — a
                // positive, auditable action, never an ambiguous absence.
                log::warn!(
                    "revocation: deny-list {} disappeared; RETAINING last-known-good \
                     revocations (write an explicit empty list to clear)",
                    self.path.display()
                );
                cache.stamp = None;
            }
            Err(e) => {
                log::warn!(
                    "revocation: keeping last-known-good; cannot read {}: {e}",
                    self.path.display()
                );
            }
        }
    }

    /// True if ANY of `ids` (each a Biscuit revocation identifier, raw bytes) is
    /// on the deny-list. Reloads the file first if it changed on disk. Because a
    /// token's revocation_identifiers always includes its AUTHORITY-block id,
    /// revoking that one id denies the token and every attenuation of it.
    pub fn is_revoked(&self, ids: &[Vec<u8>]) -> bool {
        self.refresh_if_changed();
        let cache = self.cache.read().expect("revocation cache poisoned");
        if cache.ids.is_empty() {
            return false;
        }
        ids.iter().any(|id| cache.ids.contains(&hex::encode(id)))
    }

    /// Append a revocation (idempotent: a duplicate id is not written twice) and
    /// persist the file, then update the in-memory cache. `id_hex` is a Biscuit
    /// revocation identifier, lowercase hex.
    pub fn revoke(&self, id_hex: &str, note: &str, now_ms: i64) -> Result<()> {
        let id_hex = id_hex.trim().to_ascii_lowercase();
        if id_hex.is_empty() {
            return Err(AuthError::Malformed("empty revocation id".into()));
        }
        // Read the current file (or start empty) so we append rather than clobber
        // entries another writer added — the file is the source of truth.
        let mut file = match std::fs::read(self.path.as_path()) {
            Ok(data) => serde_json::from_slice::<DenyListFile>(&data)
                .map_err(|e| AuthError::Malformed(format!("deny-list: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => DenyListFile::default(),
            Err(e) => return Err(AuthError::Io(e.to_string())),
        };
        if file
            .revoked
            .iter()
            .any(|e| e.id.trim().eq_ignore_ascii_case(&id_hex))
        {
            return Ok(()); // already revoked
        }
        file.revoked.push(RevokedEntry {
            id: id_hex,
            note: note.to_string(),
            revoked_at: now_ms,
        });
        let data = serde_json::to_vec_pretty(&file).map_err(|e| AuthError::Io(e.to_string()))?;
        std::fs::write(self.path.as_path(), data).map_err(|e| AuthError::Io(e.to_string()))?;
        // Refresh the cache from the file we just wrote (picks up the new stamp).
        let mut cache = self.cache.write().expect("revocation cache poisoned");
        cache.ids = Self::index(&file);
        cache.stamp = stamp_of(self.path.as_path());
        Ok(())
    }
}
