//! Auth errors. Every denial is a first-class, typed outcome (logged by the
//! proxy), never a panic — untrusted input must never crash the verifier.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("stale or future timestamp")]
    Freshness,
    #[error("replayed nonce")]
    Replay,
    #[error("malformed credential: {0}")]
    Malformed(String),
    #[error("invalid biscuit signature")]
    BiscuitSignature,
    #[error("proof-of-possession failed")]
    PopFailed,
    #[error("missing pubkey binding in credential")]
    MissingPubkey,
    #[error("missing identity in credential")]
    MissingIdentity,
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("nonce store: {0}")]
    Store(String),
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
