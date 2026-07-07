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

/// The identity-proving result of a per-request proof, whatever its form: the
/// pubkey the caller proved control of, a single-use replay id, and the proof's
/// timestamp (ms). The runner PoP (Ed25519 over a canonical string) and the HTTP
/// DPoP proof JWT both reduce to this before the SHARED authorization runs, so the
/// Biscuit + revocation + capability + freshness ladder lives in exactly one place
/// ([`authorize_request`]) regardless of how the caller proved possession.
pub struct ProvenIdentity {
    /// The Ed25519 public key (hex) the caller proved control of.
    pub pubkey_hex: String,
    /// The single-use replay key (runner: the nonce; DPoP: the proof `jti`).
    pub replay_id: String,
    /// The proof timestamp in epoch-ms (runner: `ts`; DPoP: `iat * 1000`).
    pub ts_ms: i64,
}

/// Verify a RUNNER request (CAS / dispatch frame) end to end: bespoke Ed25519 PoP
/// over the rebuilt canonical string, then the shared authorization ladder. Any
/// failure is a typed denial, never a panic.
///
/// `single_use` controls the nonce discipline. `true` (the default for every
/// mutating surface — CAS, the runner frame) requires the nonce to be fresh AND
/// unseen, storing it so a replay of the exact request is denied. `false` enforces
/// freshness ONLY (no such runner surface today; retained for symmetry with the
/// HTTP path). See [`verify_http_dpop`] for the browser-facing surface.
pub fn verify(
    root_pub: &PublicKey,
    nonces: &NonceStore,
    revocations: &RevocationStore,
    now_ms: i64,
    req: &AuthedRequest,
    single_use: bool,
) -> Result<Identity> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // Proof of possession over the rebuilt canonical string. The PEP never trusts
    // a client-supplied canonical — it rebuilds it from structured request fields.
    let pubkey =
        hex::decode(&req.pubkey_hex).map_err(|_| AuthError::Malformed("pubkey hex".into()))?;
    let sig = STANDARD
        .decode(&req.pop_sig_b64)
        .map_err(|_| AuthError::Malformed("pop sig b64".into()))?;
    let canonical = req.op.canonical(&req.nonce_b64, req.ts_ms);
    pop::verify_pop(&pubkey, &canonical, &sig)?;

    let proven = ProvenIdentity {
        pubkey_hex: req.pubkey_hex.clone(),
        replay_id: req.nonce_b64.clone(),
        ts_ms: req.ts_ms,
    };
    authorize_request(
        root_pub,
        nonces,
        revocations,
        now_ms,
        &req.biscuit_b64,
        req.op.required_right(),
        &req.required_lanes,
        req.address_hex.as_deref(),
        &proven,
        single_use,
    )
}

/// One authenticated HTTP request presented to the PEP's DPoP surface. The proof is
/// an RFC 9449 DPoP proof JWT (verified by [`crate::dpop`]); `htu` is the PEP-rebuilt
/// `<public-origin><path>` (no query) and `body_sha256` is the raw SHA-256 of the
/// buffered request body (the empty-body digest for a bodyless GET/HEAD).
pub struct DpopHttpRequest {
    pub method: String,
    pub htu: String,
    pub right: String,
    pub biscuit_b64: String,
    pub proof_jwt: String,
    pub body_sha256: [u8; 32],
}

/// Verify an HTTP request whose proof is a DPoP proof JWT (RFC 9449). The proof —
/// signature, method/uri/token/body binding — is checked by [`crate::dpop`]; the
/// Biscuit capability, revocation, and freshness/replay are the SAME shared ladder
/// the runner PoP uses. `single_use=true` for mutating header-auth calls; `false`
/// for signed-URL GET/HEAD reads (freshness-only, reusable within the window).
pub fn verify_http_dpop(
    root_pub: &PublicKey,
    nonces: &NonceStore,
    revocations: &RevocationStore,
    now_ms: i64,
    req: &DpopHttpRequest,
    single_use: bool,
) -> Result<Identity> {
    let proven = crate::dpop::verify_proof(
        &req.proof_jwt,
        &req.method,
        &req.htu,
        &req.biscuit_b64,
        &req.body_sha256,
    )?;
    authorize_request(
        root_pub,
        nonces,
        revocations,
        now_ms,
        &req.biscuit_b64,
        &req.right,
        &[],
        None,
        &proven,
        single_use,
    )
}

/// The authorization ladder shared by every surface, run AFTER a proof has proven
/// possession of `proven.pubkey_hex`: parse the Biscuit against the root key, apply
/// the revocation deny-list, authorize the capability (pubkey binding + required
/// right + any lanes), then enforce freshness/replay. Any failure is a typed denial.
#[allow(clippy::too_many_arguments)]
fn authorize_request(
    root_pub: &PublicKey,
    nonces: &NonceStore,
    revocations: &RevocationStore,
    now_ms: i64,
    biscuit_b64: &str,
    right: &str,
    required_lanes: &[String],
    address_hex: Option<&str>,
    proven: &ProvenIdentity,
    single_use: bool,
) -> Result<Identity> {
    // 1. Parse the Biscuit against the root key (verifies its signature chain).
    let biscuit =
        Biscuit::from_base64(biscuit_b64, *root_pub).map_err(|_| AuthError::BiscuitSignature)?;

    // 1b. Revocation: a credential is revoked by putting any of its block
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

    // 2. Authorize: bind the presented pubkey, the operation, address, and time;
    //    require the right and the pubkey match (and any required lanes).
    let mut authorizer = biscuit
        .authorizer()
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .add_fact(fact!(
            "presented_pubkey({p})",
            p = proven.pubkey_hex.clone()
        ))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .add_fact(fact!("operation({o})", o = right.to_string()))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .add_fact(fact!("now({t})", t = now_ms))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    if let Some(addr) = address_hex {
        authorizer
            .add_fact(fact!("address({a})", a = addr.to_string()))
            .map_err(|e| AuthError::Denied(e.to_string()))?;
    }
    // The presented pubkey must equal the one bound in the credential.
    authorizer
        .add_check(check!("check if pubkey($p), presented_pubkey($p)"))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    // Each required lane must be granted by the credential.
    for lane in required_lanes {
        authorizer
            .add_check(check!("check if lane({l})", l = lane.clone()))
            .map_err(|e| AuthError::Denied(e.to_string()))?;
    }
    // The credential must grant the required right.
    authorizer
        .add_policy(policy!("allow if right({o})", o = right.to_string()))
        .map_err(|e| AuthError::Denied(e.to_string()))?;
    authorizer
        .authorize()
        .map_err(|e| AuthError::Denied(e.to_string()))?;

    // 3. Freshness (+ single-use, if required) — only after the request
    //    authenticates, so unauthenticated traffic can never pollute the store.
    //    Non-single-use (signed-URL reads) is freshness-only: still rejects a
    //    stale ts, but does not store the replay id, so the URL is reusable until
    //    it expires.
    if single_use {
        nonces.check_and_store(&proven.replay_id, proven.ts_ms, now_ms)?;
    } else {
        nonces.check_freshness(proven.ts_ms, now_ms)?;
    }

    Ok(Identity {
        id: proven.pubkey_hex.clone(),
    })
}
