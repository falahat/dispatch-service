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

impl AuthError {
    /// What the client is told. A fault of the PEP's own (its nonce store, IO, its rules)
    /// says only `internal error`: its detail is for the PEP's log, never the caller.
    pub fn client_message(&self) -> String {
        match self {
            AuthError::Store(_) | AuthError::Io(_) | AuthError::Internal => {
                AuthError::Internal.to_string()
            }
            refused => refused.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fault_of_the_pep_says_only_internal_error() {
        for fault in [
            AuthError::Store("redb: database file is corrupt at /data/nonces.redb".into()),
            AuthError::Io("No space left on device (os error 28)".into()),
            AuthError::Internal,
        ] {
            assert_eq!(fault.client_message(), "internal error", "{fault:?}");
        }
    }

    #[test]
    fn a_refusal_still_says_why() {
        assert_eq!(AuthError::Replay.client_message(), "replayed nonce");
        assert_eq!(
            AuthError::Denied("no lane".into()).client_message(),
            "authorization denied: no lane"
        );
    }
}
