//! Credentials: minting a Biscuit that binds an identity to a proof-of-possession
//! key plus a set of rights and lanes, and the combined verify + authorize path.
//!
//! Design: the credential carries `pubkey(<hex>)` — the Ed25519 key the holder
//! must prove control of. The request presents that same pubkey and a PoP
//! signature; the PEP (1) verifies the PoP with the presented pubkey, (2) parses
//! the Biscuit against the root key, and (3) authorizes with a `pubkey ==
//! presented_pubkey` check, so a valid decision means the holder controls the
//! exact key the issuer bound. No fragile fact extraction, no key registry.

use crate::canonical::Op;
use crate::error::{AuthError, Result};
use crate::nonce::NonceStore;
use crate::pop;
use crate::revocation::RevocationStore;
use biscuit_auth::builder::BlockBuilder;
use biscuit_auth::macros::{check, fact, policy};
use biscuit_auth::{Biscuit, KeyPair, PublicKey};

/// Parameters for minting a credential.
pub struct MintParams {
    /// The Ed25519 public key (hex) the holder proves possession of.
    pub pubkey_hex: String,
    /// Capabilities granted (e.g. cas_get, cas_put, hello, lease, heartbeat,
    /// complete, fail, release, observe).
    pub rights: Vec<String>,
    /// Lanes this credential may serve.
    pub lanes: Vec<String>,
}

/// Mint a base credential signed by the root key. Returns the base64 token.
pub fn mint(root: &KeyPair, p: &MintParams) -> Result<String> {
    let mut b = Biscuit::builder();
    b.add_fact(fact!("pubkey({pk})", pk = p.pubkey_hex.clone()))
        .map_err(|e| AuthError::Malformed(e.to_string()))?;
    for r in &p.rights {
        b.add_fact(fact!("right({r})", r = r.clone()))
            .map_err(|e| AuthError::Malformed(e.to_string()))?;
    }
    for l in &p.lanes {
        b.add_fact(fact!("lane({l})", l = l.clone()))
            .map_err(|e| AuthError::Malformed(e.to_string()))?;
    }
    let biscuit = b
        .build(root)
        .map_err(|e| AuthError::Malformed(e.to_string()))?;
    biscuit
        .to_base64()
        .map_err(|e| AuthError::Malformed(e.to_string()))
}

/// Attenuate a credential for one lease: scope `cas_get` to a closure of
/// addresses and add an expiry. The attenuated token is used only for input
/// fetches; because attenuation can only restrict, a token scoped to job A can
/// never fetch job B's addresses. (Offline — needs no root key.)
pub fn attenuate_for_lease(
    token_b64: &str,
    root_pub: &PublicKey,
    allowed_get_hex: &[String],
    expire_ts_ms: i64,
) -> Result<String> {
    let biscuit = Biscuit::from_base64(token_b64, *root_pub)
        .map_err(|e| AuthError::Malformed(e.to_string()))?;
    let mut bb = BlockBuilder::new();
    for a in allowed_get_hex {
        bb.add_fact(fact!("allowed_get({a})", a = a.clone()))
            .map_err(|e| AuthError::Malformed(e.to_string()))?;
    }
    // A cas_get is only permitted for an allowed address.
    bb.add_check(check!(
        "check if operation(\"cas_get\"), address($a), allowed_get($a)"
    ))
    .map_err(|e| AuthError::Malformed(e.to_string()))?;
    // The lease token expires with the lease.
    bb.add_check(check!("check if now($t), $t <= {exp}", exp = expire_ts_ms))
        .map_err(|e| AuthError::Malformed(e.to_string()))?;
    let attenuated = biscuit
        .append(bb)
        .map_err(|e| AuthError::Malformed(e.to_string()))?;
    attenuated
        .to_base64()
        .map_err(|e| AuthError::Malformed(e.to_string()))
}

/// A verified identity: the holder's pubkey (hex), which doubles as the runner
/// id (a public-key fingerprint) in the fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
}

/// One authenticated request presented to the PEP.
pub struct AuthedRequest {
    pub op: Op,
    pub biscuit_b64: String,
    pub pubkey_hex: String,
    pub nonce_b64: String,
    pub ts_ms: i64,
    pub pop_sig_b64: String,
    /// Lanes the request needs granted (lease); empty otherwise.
    pub required_lanes: Vec<String>,
    /// The CAS blob hex, for address-scoped checks; None for dispatch ops.
    pub address_hex: Option<String>,
}

/// Verify a request end to end: PoP, Biscuit signature, capability authorization,
/// and freshness. Any failure is a typed denial, never a panic.
///
/// `single_use` controls the nonce discipline. `true` (the default for every
/// mutating surface — CAS, the runner frame, header-auth HTTP) requires the
/// nonce to be fresh AND unseen, storing it so a replay of the exact request is
/// denied. `false` (signed-URL query-auth reads) enforces freshness ONLY: the
/// timestamp must be within the window (so a signed URL still EXPIRES), but the
/// nonce is not stored, so a browser reusing one signed URL across range
/// requests / retries is not replay-rejected. Only idempotent GET/HEAD reads are
/// allowed to run non-single-use (enforced at route-table boot time).
pub fn verify(
    root_pub: &PublicKey,
    nonces: &NonceStore,
    revocations: &RevocationStore,
    now_ms: i64,
    req: &AuthedRequest,
    single_use: bool,
) -> Result<Identity> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // 1. Proof of possession over the rebuilt canonical string.
    let pubkey =
        hex::decode(&req.pubkey_hex).map_err(|_| AuthError::Malformed("pubkey hex".into()))?;
    let sig = STANDARD
        .decode(&req.pop_sig_b64)
        .map_err(|_| AuthError::Malformed("pop sig b64".into()))?;
    let canonical = req.op.canonical(&req.nonce_b64, req.ts_ms);
    pop::verify_pop(&pubkey, &canonical, &sig)?;

    // 2. Parse the Biscuit against the root key (verifies its signature chain).
    let biscuit = Biscuit::from_base64(&req.biscuit_b64, *root_pub)
        .map_err(|_| AuthError::BiscuitSignature)?;

    // 2b. Revocation: a credential is revoked by putting any of its block
    //     revocation identifiers on the deny-list. `revocation_identifiers()`
    //     ALWAYS includes the authority-block id (index 0), which every
    //     attenuation inherits — so revoking the authority id denies the base
    //     credential AND every token attenuated from it. Checked after the
    //     signature parse (so only a genuinely-signed credential is measured
    //     against the list) and before authorization (a revoked credential is
    //     denied regardless of the right it would otherwise grant).
    if revocations.is_revoked(&biscuit.revocation_identifiers()) {
        return Err(AuthError::Revoked);
    }

    // 3. Authorize: bind the presented pubkey, the operation, address, and time;
    //    require the right and the pubkey match (and any required lanes).
    let right = req.op.required_right().to_string();
    let mut authorizer = biscuit
        .authorizer()
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .add_fact(fact!("presented_pubkey({p})", p = req.pubkey_hex.clone()))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .add_fact(fact!("operation({o})", o = right.clone()))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .add_fact(fact!("now({t})", t = now_ms))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    if let Some(addr) = &req.address_hex {
        authorizer
            .add_fact(fact!("address({a})", a = addr.clone()))
            .map_err(|e| AuthError::Denied(e.to_string()))?;
    }
    // The presented pubkey must equal the one bound in the credential.
    authorizer
        .add_check(check!("check if pubkey($p), presented_pubkey($p)"))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    // Each required lane must be granted by the credential.
    for lane in &req.required_lanes {
        authorizer
            .add_check(check!("check if lane({l})", l = lane.clone()))
            .map_err(|e| AuthError::Denied(e.to_string()))?;
    }
    // The credential must grant the required right.
    authorizer
        .add_policy(policy!("allow if right({o})", o = right.clone()))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .authorize()
        .map_err(|e| AuthError::Denied(e.to_string()))?;

    // 4. Freshness (+ single-use, if required) — only after the request
    //    authenticates, so unauthenticated traffic can never pollute the store.
    //    Non-single-use (signed-URL reads) is freshness-only: still rejects a
    //    stale ts, but does not store the nonce, so the URL is reusable until it
    //    expires.
    if single_use {
        nonces.check_and_store(&req.nonce_b64, req.ts_ms, now_ms)?;
    } else {
        nonces.check_freshness(req.ts_ms, now_ms)?;
    }

    Ok(Identity {
        id: req.pubkey_hex.clone(),
    })
}
