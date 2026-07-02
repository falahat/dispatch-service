//! Proof of possession: the holder of a credential proves it controls the
//! private key bound in the credential by signing the canonical request string.
//! This is what stops a stolen bearer token from being replayed by a thief —
//! the thief lacks the private key.

use crate::error::{AuthError, Result};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify an Ed25519 proof-of-possession over `canonical`.
pub fn verify_pop(pubkey: &[u8], canonical: &str, sig: &[u8]) -> Result<()> {
    let key_bytes: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| AuthError::Malformed("pubkey length".into()))?;
    let vk = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| AuthError::Malformed("bad pubkey".into()))?;
    let sig = Signature::from_slice(sig).map_err(|_| AuthError::Malformed("bad signature".into()))?;
    vk.verify_strict(canonical.as_bytes(), &sig)
        .map_err(|_| AuthError::PopFailed)
}
