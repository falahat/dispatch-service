//! Credentials: minting a Biscuit that binds an identity to a proof-of-possession
//! key plus a set of rights and lanes, and the combined verify + authorize path.
//!
//! Design: the credential carries `pubkey(<hex>)` — the Ed25519 key the holder
//! must prove control of. The request presents that same pubkey and a PoP
//! signature; the PEP (1) verifies the PoP with the presented pubkey, (2) parses
//! the Biscuit against the root key, and (3) authorizes with a `pubkey ==
//! presented_pubkey` check, so a valid decision means the holder controls the
//! exact key the issuer bound. No fragile fact extraction, no key registry.

use std::time::Duration;

use crate::canonical::Op;
use crate::error::{AuthError, Result};
use crate::nonce::NonceStore;
use crate::policy;
use crate::pop;
use crate::revocation::RevocationStore;
// Facts are built from typed terms; the checks, policy and query come from crate::policy,
// biscuit's own Datalog text parsed once, with every `{param}` bound by `set` to a typed
// term. A bound value is never spliced into the text, so a caller's string cannot change
// the rule it lands in. (biscuit's compile-time macros are off: their proc-macro crate is
// unmaintained.)
use biscuit_auth::builder::{fact, int, string, BlockBuilder};
use biscuit_auth::error::Token as BiscuitError;
use biscuit_auth::{AuthorizerLimits, Biscuit, KeyPair, PublicKey};

/// Wall-clock backstop for the Datalog authorize. biscuit measures `max_time` as `Instant`
/// elapsed over the WHOLE authorize call, so the library default of 1 ms made a
/// structurally-valid credential's verdict a function of host CPU scheduling: under the
/// 2026-07 transcribe backfill that pegged all 24 cores, trivial authorizes were preempted
/// past 1 ms and biscuit fail-closed-403'd healthy runner lease/heartbeat/CAS frames (the
/// "Reached Datalog execution limits" brownout). A generous budget cannot be crossed by
/// scheduler jitter; the DETERMINISTIC fact/iteration caps (kept at the biscuit defaults via
/// `..Default::default()`) remain the real DoS guard against a hostile fact-generating token.
const AUTHZ_MAX_TIME: Duration = Duration::from_secs(5);

/// Deterministic ceilings on the Datalog evaluation — THE DoS guard, in the one unit a
/// hostile token controls and a busy host does not. A genuine credential contributes a
/// pubkey fact, a right per capability, a lane per lane, and the request's own checks: tens
/// of facts and a couple of iterations. These bounds leave enormous headroom for that while
/// still stopping an attenuation block that tries to generate facts combinatorially, and —
/// unlike a wall-clock budget — they fail identically on an idle box and a pegged one.
const AUTHZ_MAX_FACTS: u64 = 1000;
const AUTHZ_MAX_ITERATIONS: u64 = 100;

/// Hard ceiling on a presented credential's base64 length, enforced BEFORE the biscuit is
/// parsed — the bound that actually constrains attacker-supplied token CONTENT.
///
/// `max_facts` limits facts DERIVED during evaluation, not facts DECLARED in blocks, so it
/// does not stop a token that simply carries thousands of them. Attenuation needs no root key,
/// so any holder can self-attenuate and hand the PEP a half-megabyte credential to base64-decode,
/// signature-verify, and evaluate on EVERY request. Measured sizes: a base credential is 372
/// bytes, a real lease-scoped one ~780, an implausibly broad 50-address scope under 6 KiB — and
/// a 5000-fact bomb 508 KiB. This ceiling leaves ~300 addresses of headroom and still refuses
/// that bomb by more than an order of magnitude.
const MAX_BISCUIT_B64_LEN: usize = 32 * 1024;

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
    let malformed = |e: BiscuitError| AuthError::Malformed(e.to_string());
    let mut b = Biscuit::builder();
    b.add_fact(fact("pubkey", &[string(&p.pubkey_hex)]))
        .map_err(malformed)?;
    for r in &p.rights {
        b.add_fact(fact("right", &[string(r)])).map_err(malformed)?;
    }
    for l in &p.lanes {
        b.add_fact(fact("lane", &[string(l)])).map_err(malformed)?;
    }
    let biscuit = b.build(root).map_err(malformed)?;
    biscuit.to_base64().map_err(malformed)
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
    let malformed = |e: BiscuitError| AuthError::Malformed(e.to_string());
    let biscuit = Biscuit::from_base64(token_b64, *root_pub).map_err(malformed)?;
    let mut bb = BlockBuilder::new();
    for a in allowed_get_hex {
        bb.add_fact(fact("allowed_get", &[string(a)]))
            .map_err(malformed)?;
    }
    // A cas_get is only permitted for an allowed address.
    bb.add_check(policy::lease_gets()?).map_err(internal)?;
    // The lease token expires with the lease.
    bb.add_check(policy::expiry(expire_ts_ms)?)
        .map_err(internal)?;
    let attenuated = biscuit.append(bb).map_err(malformed)?;
    attenuated.to_base64().map_err(malformed)
}

/// The rights a credential's authority block grants, or None when they cannot be read. It
/// runs no check, so an attenuation's checks cannot hide a right, and the query sees only
/// authority facts, so an attenuation cannot add one.
pub fn authority_rights(token_b64: &str, root_pub: &PublicKey) -> Option<Vec<String>> {
    let biscuit = Biscuit::from_base64(token_b64, *root_pub).ok()?;
    let mut authorizer = biscuit.authorizer().ok()?;
    let rights: Vec<(String,)> = authorizer
        .query_with_limits(
            policy::rights_query().ok()?,
            AuthorizerLimits {
                max_time: AUTHZ_MAX_TIME,
                max_facts: AUTHZ_MAX_FACTS,
                max_iterations: AUTHZ_MAX_ITERATIONS,
            },
        )
        .ok()?;
    Some(rights.into_iter().map(|(right,)| right).collect())
}

/// The PEP's own rule failed to go into an authorizer or block: a PEP bug, so it is denied
/// as one, with nothing for the caller to read.
fn internal(_: BiscuitError) -> AuthError {
    AuthError::Internal
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
    // 0. Bound the credential BEFORE spending any work on it. Parsing, verifying the
    //    signature chain, and evaluating Datalog are all proportional to token size, and a
    //    holder can self-attenuate to any size they like — so this cap, not the Datalog
    //    limits, is what stops a credential-shaped DoS.
    if biscuit_b64.len() > MAX_BISCUIT_B64_LEN {
        return Err(AuthError::Malformed("credential too large".into()));
    }
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
    let denied = |e: BiscuitError| AuthError::Denied(e.to_string());
    let mut authorizer = biscuit.authorizer().map_err(denied)?;
    authorizer
        .add_fact(fact("presented_pubkey", &[string(&proven.pubkey_hex)]))
        .map_err(denied)?;
    authorizer
        .add_fact(fact("operation", &[string(right)]))
        .map_err(denied)?;
    authorizer
        .add_fact(fact("now", &[int(now_ms)]))
        .map_err(denied)?;
    if let Some(addr) = address_hex {
        authorizer
            .add_fact(fact("address", &[string(addr)]))
            .map_err(denied)?;
    }
    // The presented pubkey must equal the one bound in the credential.
    authorizer
        .add_check(policy::pubkey_bound()?)
        .map_err(internal)?;
    // Each required lane must be granted by the credential.
    for lane in required_lanes {
        authorizer
            .add_check(policy::lane_granted(lane)?)
            .map_err(internal)?;
    }
    // The credential must grant the required right.
    authorizer
        .add_policy(policy::right_granted(right)?)
        .map_err(internal)?;
    // The DoS guard is DETERMINISTIC (facts/iterations), never the clock. A real credential is
    // tiny — a pubkey fact, a few rights and lanes, and the checks added above — so these
    // ceilings sit far above anything legitimate and far below what a fact-generating
    // attenuation needs. Being functions of token CONTENT, they cannot be moved by host load,
    // which is precisely the property `max_time` lacked. Set explicitly rather than left to
    // `..Default::default()` so the guard is stated here and cannot drift with a dependency
    // bump.
    authorizer.set_limits(AuthorizerLimits {
        max_time: AUTHZ_MAX_TIME,
        max_facts: AUTHZ_MAX_FACTS,
        max_iterations: AUTHZ_MAX_ITERATIONS,
    });
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
