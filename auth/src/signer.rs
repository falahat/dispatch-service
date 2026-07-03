//! The credential signer (mint). It holds the issuer (root) private key — the
//! only component that does — and mints Biscuit credentials for runners and
//! apps. The secrets file preserves the existing issuer key and the pairing
//! registry: re-keying would force re-enrolling every device, so the cutover
//! keeps this format byte-compatible.

use crate::cred::{mint, MintParams};
use crate::error::{AuthError, Result};
use crate::revocation::RevocationStore;
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey};
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
    /// The authority-block revocation identifier (lowercase hex) of this
    /// identity's minted credential, recorded at enrollment. Revoking pushes this
    /// onto the PEP's deny-list — and because every attenuation of the credential
    /// inherits the authority id, one entry kills the credential and all its
    /// leases. Empty until the identity is enrolled (defaulted for older files).
    #[serde(default)]
    pub revocation_id: String,
}

/// The deployed key file: easy-podcast's `SecretStore` format, whose issuer key
/// lives under `secrets.worker_issuer_ed25519_sk` as HEX of the 32-byte Ed25519
/// seed. The Python signer owns this file; the plane signer only READS it — the
/// key volume can (and should) be mounted read-only.
#[derive(Debug, Deserialize)]
struct SecretStoreFile {
    secrets: BTreeMap<String, String>,
}

/// The key under which the issuer seed lives in the deployed SecretStore.
const ISSUER_KEY_NAME: &str = "worker_issuer_ed25519_sk";

/// A fresh plane's own key file (no Python signer present): base64 of the seed.
#[derive(Debug, Serialize, Deserialize)]
struct PlaneKeyFile {
    issuer_private_key_b64: String,
}

/// The plane's pairing registry — its OWN file, never the key file (the key
/// file may be read-only and is owned by the phone trust plane).
#[derive(Debug, Default, Serialize, Deserialize)]
struct PairingsFile {
    #[serde(default)]
    pairings: BTreeMap<String, Pairing>,
}

/// The running signer.
pub struct Signer {
    keypair: KeyPair,
    pairings: BTreeMap<String, Pairing>,
    pairings_path: std::path::PathBuf,
}

impl Signer {
    /// Open the signer against a key file + a pairing-registry file.
    ///
    /// The key file is either the DEPLOYED easy-podcast SecretStore
    /// (`{"secrets": {"worker_issuer_ed25519_sk": "<hex>"}}` — read-only, the
    /// existing issuer key is PRESERVED so no device re-pairs) or this signer's
    /// own `{"issuer_private_key_b64": ...}`; a missing key file mints a fresh
    /// key in the latter format. Pairings always live in `pairings_path`.
    pub fn open_with<P: AsRef<Path>, Q: AsRef<Path>>(
        key_path: P,
        pairings_path: Q,
    ) -> Result<Self> {
        let key_path = key_path.as_ref().to_path_buf();
        let pairings_path = pairings_path.as_ref().to_path_buf();
        let keypair = if key_path.exists() {
            let data = std::fs::read(&key_path).map_err(|e| AuthError::Io(e.to_string()))?;
            Self::keypair_from_file(&data)?
        } else {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let keypair = KeyPair::new();
            let fresh = PlaneKeyFile {
                issuer_private_key_b64: STANDARD.encode(keypair.private().to_bytes()),
            };
            let data =
                serde_json::to_vec_pretty(&fresh).map_err(|e| AuthError::Io(e.to_string()))?;
            std::fs::write(&key_path, data).map_err(|e| AuthError::Io(e.to_string()))?;
            keypair
        };
        let pairings = if pairings_path.exists() {
            let data = std::fs::read(&pairings_path).map_err(|e| AuthError::Io(e.to_string()))?;
            let file: PairingsFile =
                serde_json::from_slice(&data).map_err(|e| AuthError::Malformed(e.to_string()))?;
            file.pairings
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            keypair,
            pairings,
            pairings_path,
        })
    }

    /// Open with the default pairing registry next to the key file
    /// (`plane-pairings.json`).
    pub fn open<P: AsRef<Path>>(key_path: P) -> Result<Self> {
        let key_path = key_path.as_ref().to_path_buf();
        let pairings = key_path.with_file_name("plane-pairings.json");
        Self::open_with(key_path, pairings)
    }

    /// Parse whichever key-file format is present.
    fn keypair_from_file(data: &[u8]) -> Result<KeyPair> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        // The deployed SecretStore shape first (the live format on the host).
        if let Ok(store) = serde_json::from_slice::<SecretStoreFile>(data) {
            if let Some(hex_sk) = store.secrets.get(ISSUER_KEY_NAME) {
                let priv_bytes = hex::decode(hex_sk)
                    .map_err(|_| AuthError::Malformed("issuer key hex".into()))?;
                let private = PrivateKey::from_bytes(&priv_bytes)
                    .map_err(|e| AuthError::Malformed(e.to_string()))?;
                return Ok(KeyPair::from(&private));
            }
        }
        // This signer's own format.
        if let Ok(own) = serde_json::from_slice::<PlaneKeyFile>(data) {
            let priv_bytes = STANDARD
                .decode(&own.issuer_private_key_b64)
                .map_err(|_| AuthError::Malformed("issuer key b64".into()))?;
            let private = PrivateKey::from_bytes(&priv_bytes)
                .map_err(|e| AuthError::Malformed(e.to_string()))?;
            return Ok(KeyPair::from(&private));
        }
        Err(AuthError::Malformed(
            "key file is neither a SecretStore nor a plane key file".into(),
        ))
    }

    fn save(&self) -> Result<()> {
        let file = PairingsFile {
            pairings: self.pairings.clone(),
        };
        let data = serde_json::to_vec_pretty(&file).map_err(|e| AuthError::Io(e.to_string()))?;
        std::fs::write(&self.pairings_path, data).map_err(|e| AuthError::Io(e.to_string()))
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

    /// Enroll (pair) an identity, mint its credential, and record the
    /// credential's authority-block revocation identifier on the pairing (so it
    /// can later be revoked without re-deriving it). Returns the minted token.
    pub fn enroll(&mut self, pairing: Pairing) -> Result<String> {
        let id = pairing.pubkey_hex.clone();
        self.pairings.insert(id.clone(), pairing);
        let cred = self.mint_for(&id)?;
        // Record the authority revocation id so `revoke` needs no re-derivation.
        let rev_id = authority_revocation_id(&cred, &self.keypair.public())?;
        if let Some(p) = self.pairings.get_mut(&id) {
            p.revocation_id = rev_id;
        }
        self.save()?;
        Ok(cred)
    }

    /// Mint a credential for an already-enrolled identity.
    pub fn mint_for(&self, id: &str) -> Result<String> {
        let p = self
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

    /// Revoke an enrolled identity: append its recorded authority-block
    /// revocation id to the PEP's deny-list file (creating it if absent) and
    /// persist. The PEP live-reloads the file, so the next request bearing that
    /// credential — or any lease attenuated from it — is denied. Idempotent.
    pub fn revoke<P: AsRef<Path>>(
        &mut self,
        pubkey_hex: &str,
        deny_list_path: P,
        now_ms: i64,
    ) -> Result<()> {
        let p = self
            .pairings
            .get(pubkey_hex)
            .ok_or_else(|| AuthError::Denied(format!("unknown identity {pubkey_hex}")))?;
        if p.revocation_id.is_empty() {
            return Err(AuthError::Malformed(format!(
                "identity {pubkey_hex} has no recorded revocation id (re-enroll to mint one)"
            )));
        }
        let note = format!(
            "revoked pairing {pubkey_hex}{}",
            p.note
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        );
        // Reuse the deny-list writer so the on-disk format stays single-sourced.
        let deny = RevocationStore::open(&deny_list_path)?;
        deny.revoke(&p.revocation_id, &note, now_ms)
    }

    /// The enrolled pairings (read-only).
    pub fn pairings(&self) -> &BTreeMap<String, Pairing> {
        &self.pairings
    }
}

/// The authority-block revocation identifier (lowercase hex) of a minted token,
/// parsed against `root` (its issuer). This is the id an operator puts on the
/// deny-list to revoke the credential.
fn authority_revocation_id(cred_b64: &str, root: &PublicKey) -> Result<String> {
    let biscuit =
        Biscuit::from_base64(cred_b64, *root).map_err(|e| AuthError::Malformed(e.to_string()))?;
    let ids = biscuit.revocation_identifiers();
    let authority = ids
        .first()
        .ok_or_else(|| AuthError::Malformed("credential has no revocation id".into()))?;
    Ok(hex::encode(authority))
}
