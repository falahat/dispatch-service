//! The dispatch plane's single auth engine (Rust): Biscuit + PoP verification
//! and the credential signer. It is the only place any credential is verified;
//! backends receive pre-authenticated requests over loopback and hold no auth
//! crypto. See docs/TRUST_PLANE.md.

pub mod canonical;
pub mod cas_proxy;
pub mod cred;
pub mod error;
pub mod frame_proxy;
pub mod http_proxy;
pub mod nonce;
pub mod pop;
pub mod quota;
pub mod signer;

pub use canonical::Op;
pub use cred::{attenuate_for_lease, mint, verify, AuthedRequest, Identity, MintParams};
pub use error::{AuthError, Result};
pub use nonce::{NonceStore, DEFAULT_WINDOW_MS};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests;
