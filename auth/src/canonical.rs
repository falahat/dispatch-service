//! Canonical request strings — the exact bytes a proof-of-possession signs.
//! One source of truth for both the runner (Go) and the PEP (Rust): the PEP
//! rebuilds the canonical string from structured request fields rather than
//! trusting a client-supplied string.

/// The operation an authenticated request performs, with everything needed to
/// rebuild its canonical string and to name the required capability.
#[derive(Debug, Clone)]
pub enum Op {
    /// A CAS request. Canonical: `cas/v0 <METHOD> <path> <nonce> <ts>`.
    /// The address in the path IS the content commitment for PUT, so the
    /// signature binds the bytes without hashing twice.
    Cas { method: String, path: String },
    /// A dispatcher runner-surface request. Canonical:
    /// `dispatch/v0 <verb> <sha256hex(inner_frame_bytes)> <nonce> <ts>`.
    Dispatch { verb: String, frame_sha256_hex: String },
}

impl Op {
    /// Rebuild the canonical string that the PoP signature must cover.
    pub fn canonical(&self, nonce_b64: &str, ts_ms: i64) -> String {
        match self {
            Op::Cas { method, path } => {
                format!("cas/v0 {} {} {} {}", method, path, nonce_b64, ts_ms)
            }
            Op::Dispatch { verb, frame_sha256_hex } => {
                format!("dispatch/v0 {} {} {} {}", verb, frame_sha256_hex, nonce_b64, ts_ms)
            }
        }
    }

    /// The right (capability) this operation requires.
    pub fn required_right(&self) -> &str {
        match self {
            Op::Cas { method, .. } => match method.as_str() {
                "GET" | "HEAD" => "cas_get",
                "PUT" => "cas_put",
                _ => "cas_deny",
            },
            Op::Dispatch { verb, .. } => verb.as_str(),
        }
    }
}
