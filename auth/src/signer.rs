//! The credential signer (mint). It holds the issuer (root) private key — the
//! only component that does — and mints Biscuit credentials for runners and
//! apps. The secrets file preserves the existing issuer key and the pairing
//! registry: re-keying would force re-enrolling every device, so the cutover
//! keeps this format byte-compatible.

use crate::cred::{mint, MintParams};
use crate::error::{AuthError, Result};
use biscuit_auth::{KeyPair, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// One enrolled identity's capabilities. Pairing is the root of trust and is
/// established out of band (CLI), never over a network endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pairing {
    pub pubkey_hex: String,
    pub rights: Vec<String>,
    pub lanes: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// The signer's on-disk secrets: the issuer private key and the pairing
/// registry. This is the format preserved across the trust-plane cutover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secrets {
    /// Base64 of the 32-byte Ed25519 issuer private key.
    pub issuer_private_key_b64: String,
    /// identity (== pubkey_hex) -> pairing.
    #[serde(default)]
    pub pairings: BTreeMap<String, Pairing>,
}

/// The running signer.
pub struct Signer {
    keypair: KeyPair,
    secrets: Secrets,
    path: std::path::PathBuf,
}

impl Signer {
    /// Open the signer, creating a fresh issuer key + empty registry if the file
    /// is absent.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let data = std::fs::read(&path).map_err(|e| AuthError::Io(e.to_string()))?;
            let secrets: Secrets =
                serde_json::from_slice(&data).map_err(|e| AuthError::Malformed(e.to_string()))?;
            let priv_bytes = STANDARD
                .decode(&secrets.issuer_private_key_b64)
                .map_err(|_| AuthError::Malformed("issuer key b64".into()))?;
            let private = PrivateKey::from_bytes(&priv_bytes)
                .map_err(|e| AuthError::Malformed(e.to_string()))?;
            let keypair = KeyPair::from(&private);
            Ok(Self { keypair, secrets, path })
        } else {
            let keypair = KeyPair::new();
            let priv_b64 = STANDARD.encode(keypair.private().to_bytes());
            let secrets = Secrets { issuer_private_key_b64: priv_b64, pairings: BTreeMap::new() };
            let s = Self { keypair, secrets, path };
            s.save()?;
            Ok(s)
        }
    }

    fn save(&self) -> Result<()> {
        let data =
            serde_json::to_vec_pretty(&self.secrets).map_err(|e| AuthError::Io(e.to_string()))?;
        std::fs::write(&self.path, data).map_err(|e| AuthError::Io(e.to_string()))
    }

    /// The root public key backends use to verify (the PEP holds only this).
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Base64 of the root public key.
    pub fn public_key_b64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(self.keypair.public().to_bytes())
    }

    /// Enroll (pair) an identity and persist it, then mint its credential.
    pub fn enroll(&mut self, pairing: Pairing) -> Result<String> {
        let id = pairing.pubkey_hex.clone();
        self.secrets.pairings.insert(id.clone(), pairing.clone());
        self.save()?;
        self.mint_for(&id)
    }

    /// Mint a credential for an already-enrolled identity.
    pub fn mint_for(&self, id: &str) -> Result<String> {
        let p = self
            .secrets
            .pairings
            .get(id)
            .ok_or_else(|| AuthError::Denied(format!("unknown identity {id}")))?;
        mint(
            &self.keypair,
            &MintParams {
                pubkey_hex: p.pubkey_hex.clone(),
                rights: p.rights.clone(),
                lanes: p.lanes.clone(),
            },
        )
    }

    /// The enrolled pairings (read-only).
    pub fn pairings(&self) -> &BTreeMap<String, Pairing> {
        &self.secrets.pairings
    }
}
