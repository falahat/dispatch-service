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
    #[error("dpop proof rejected: {0}")]
    DpopFailed(String),
    #[error("missing pubkey binding in credential")]
    MissingPubkey,
    #[error("missing identity in credential")]
    MissingIdentity,
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("credential revoked")]
    Revoked,
    #[error("nonce store: {0}")]
    Store(String),
    #[error("io: {0}")]
    Io(String),
    /// The PEP's own Datalog failed to bind: a PEP bug, never the caller's fault. It says
    /// nothing more, so no parser detail reaches a client; [`crate::policy::check`] catches
    /// such a bug at boot.
    #[error("internal error")]
    Internal,
}

pub type Result<T> = std::result::Result<T, AuthError>;
